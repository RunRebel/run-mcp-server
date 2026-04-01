import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { Octokit } from "octokit";
import { GitHubHandler } from "./github-handler";

// IMPORTANTE: Asegúrate de que github-handler.ts esté en la misma carpeta
// Si está en otra carpeta, ajusta el import: "./path/to/github-handler"

// Context from the auth process, encrypted & stored in the auth token
// and provided to the DurableMCP as this.props
type Props = {
  login: string;
  name: string;
  email: string;
  accessToken: string;
  tokenCreatedAt?: number; // Added for token age tracking
  isCustomApp?: boolean;
  rateLimit?: {
    remaining: number;
    limit: number;
    reset: number;
  };
};

// Validation schemas with security limits
const githubUsernameSchema = z.string().regex(/^[a-zA-Z0-9-]+$/, "Invalid GitHub username format").max(39); // GitHub limit
const githubRepoNameSchema = z.string().regex(/^[a-zA-Z0-9._-]+$/, "Invalid repository name format").max(100); // GitHub limit
const githubBranchNameSchema = z.string().regex(/^[a-zA-Z0-9/_.-]+$/, "Invalid branch name format").max(255); // Prevent ReDoS
const githubPathSchema = z.string().regex(/^[^\.\/][a-zA-Z0-9-_\.\/]*$/, "Invalid file path - no traversal allowed").max(255);
const perPageSchema = z.number().min(1).max(100).default(30).optional();

// Constants
const FILE_SIZE_LIMIT = 1024 * 1024; // 1MB
const BATCH_SIZE = 10; // For concurrent operations
const RATE_LIMIT_WARNING_THRESHOLD = 100;
const MAX_SEARCH_RESULTS_WARNING = 1000;
const MAX_PAGES = 100; // Maximum pagination limit
const OPERATION_TIMEOUT = 300000; // 5 minutes
const MAX_CONSECUTIVE_FAILURES = 5;
const CIRCUIT_BREAKER_RESET_TIME = 30000; // 30 seconds

// Sensitive field names to redact
const SENSITIVE_FIELDS = ['token', 'secret', 'password', 'key', 'auth', 'credential'];

// Binary file extensions
const BINARY_EXTENSIONS = /\.(jpg|jpeg|png|gif|pdf|zip|exe|bin|dmg|iso|tar|gz|7z|mp4|mp3|mov|avi)$/i;

export class MyMCP extends McpAgent<Env, {}, Props> {
  server = new McpServer({
    name: "GitHub MCP Server",
    version: "2.0.0",
  });

  // Cache for rate limit status
  private rateLimitCache: { checked: number; data: any } | null = null;
  private rateLimitInFlight = false;
  private readonly RATE_LIMIT_CACHE_TTL = 60000; // 1 minute

  // Circuit breaker state
  private consecutiveFailures = 0;
  private circuitBreakerOpenUntil = 0;

  async init() {
    // Helper function for error handling with context
    const handleError = (error: unknown, context?: string): string => {
      // Increment failure counter for circuit breaker
      this.consecutiveFailures++;
      
      // Check if circuit breaker should open
      if (this.consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
        this.circuitBreakerOpenUntil = Date.now() + CIRCUIT_BREAKER_RESET_TIME;
      }

      const errorMessage = error instanceof Error ? error.message : String(error);
      
      // Check for specific error types
      if (error && typeof error === 'object' && 'status' in error) {
        const status = (error as any).status;
        if (status === 401) {
          const tokenAge = this.props.tokenCreatedAt 
            ? Date.now() - this.props.tokenCreatedAt 
            : null;
          return JSON.stringify({
            error: "Authentication failed",
            message: "Your GitHub token may have expired or been revoked. Please re-authenticate.",
            token_age_hours: tokenAge ? Math.floor(tokenAge / (1000 * 60 * 60)) : "unknown",
            context
          });
        } else if (status === 403) {
          return JSON.stringify({
            error: "Permission denied",
            message: "You don't have permission to perform this action. This might be due to repository permissions or rate limiting.",
            context
          });
        } else if (status === 404) {
          return JSON.stringify({
            error: "Not found",
            message: "The requested resource was not found. Please check the owner, repository, and resource names.",
            context
          });
        } else if (status === 422) {
          return JSON.stringify({
            error: "Validation failed",
            message: "The request was invalid. Please check your input parameters.",
            details: (error as any).response?.data?.errors || [],
            context
          });
        } else if (status === 429) {
          return JSON.stringify({
            error: "Rate limit exceeded",
            message: "GitHub API rate limit exceeded. Please wait before making more requests.",
            reset_time: (error as any).response?.headers?.['x-ratelimit-reset'] 
              ? new Date(parseInt((error as any).response.headers['x-ratelimit-reset']) * 1000).toISOString()
              : "unknown",
            context
          });
        }
      }
      
      // Sanitize error message to prevent token leakage
      const sanitized = errorMessage
        .replace(/[a-f0-9]{40}/gi, '[REDACTED_TOKEN]') // GitHub tokens
        .replace(/Bearer\s+[^\s]+/gi, 'Bearer [REDACTED]') // Bearer tokens
        .replace(/https:\/\/[^@]+@/g, 'https://[REDACTED]@'); // URLs with auth
      
      return context ? `Error in ${context}: ${sanitized}` : `Error: ${sanitized}`;
    };

    // Helper function to encode content for Cloudflare Workers (UTF-8 safe)
    const encodeContent = (content: string): string => {
      const bytes = new TextEncoder().encode(content);
      let binary = '';
      bytes.forEach(byte => binary += String.fromCharCode(byte));
      return btoa(binary);
    };

    // Helper function to decode base64 content
    const decodeBase64 = (base64: string): string => {
      try {
        // atob() only handles Latin-1/ASCII byte values.
        // Files with Unicode characters (→, ⊊, λ, á, é, ñ, etc.)
        // produce garbled text or throw, causing a generic
        // "Error occurred during tool execution" from the MCP layer.
        // Fix: decode via Uint8Array + TextDecoder('utf-8').
        const binary = atob(base64.replace(/\n/g, ''));
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
          bytes[i] = binary.charCodeAt(i);
        }
        return new TextDecoder('utf-8').decode(bytes);
      } catch {
        return base64; // Return as-is if decode fails
      }
    };

    // Helper to check rate limits with caching
    const checkRateLimit = async (octokit: Octokit): Promise<{ canContinue: boolean; warning?: string; remaining?: number }> => {
      // Check circuit breaker
      if (Date.now() < this.circuitBreakerOpenUntil) {
        return {
          canContinue: false,
          warning: `Circuit breaker open due to multiple failures. Retry after ${new Date(this.circuitBreakerOpenUntil).toISOString()}`
        };
      }

      try {
        // Use cached data if fresh
        if (this.rateLimitCache && (Date.now() - this.rateLimitCache.checked < this.RATE_LIMIT_CACHE_TTL)) {
          const remaining = this.rateLimitCache.data.rate.remaining;
          if (remaining < RATE_LIMIT_WARNING_THRESHOLD) {
            return {
              canContinue: remaining > 0,
              warning: `Low API rate limit: ${remaining} calls remaining. Resets at ${new Date(this.rateLimitCache.data.rate.reset * 1000).toISOString()}`,
              remaining
            };
          }
          return { canContinue: true, remaining };
        }

        // Prevent thundering herd
        if (this.rateLimitInFlight) {
          await new Promise(resolve => setTimeout(resolve, 50));
          if (this.rateLimitCache) {
            const remaining = this.rateLimitCache.data.rate.remaining;
            return { canContinue: remaining > 0, remaining };
          }
          return { canContinue: true };
        }

        this.rateLimitInFlight = true;
        try {
          // Fetch fresh rate limit data
          const { data: rateLimit } = await octokit.rest.rateLimit.get();
          this.rateLimitCache = { checked: Date.now(), data: rateLimit };
          
          // Reset consecutive failures on success
          this.consecutiveFailures = 0;
          
          if (rateLimit.rate.remaining < RATE_LIMIT_WARNING_THRESHOLD) {
            return {
              canContinue: rateLimit.rate.remaining > 0,
              warning: `Low API rate limit: ${rateLimit.rate.remaining} calls remaining. Resets at ${new Date(rateLimit.rate.reset * 1000).toISOString()}`,
              remaining: rateLimit.rate.remaining
            };
          }
          return { canContinue: true, remaining: rateLimit.rate.remaining };
        } finally {
          this.rateLimitInFlight = false;
        }
      } catch {
        // If rate limit check fails, allow continuation but warn
        return { canContinue: true, warning: "Could not check rate limit status" };
      }
    };

    // Helper to limit search results and add warnings
    const limitSearchResults = (data: any, itemsLength: number) => {
      if (data.total_count > MAX_SEARCH_RESULTS_WARNING) {
        return {
          warning: `Found ${data.total_count} results. Showing first ${itemsLength}. Use more specific search terms.`,
          total_count: data.total_count,
          incomplete_results: data.incomplete_results || true,
          items: data.items || []
        };
      }
      return data;
    };

    // Helper to sanitize sensitive data from responses
    const sanitizeResponse = (data: any): any => {
      if (!data || typeof data !== 'object') return data;
      
      const cleaned = Array.isArray(data) ? [...data] : { ...data };
      
      const sanitizeObject = (obj: any) => {
        Object.keys(obj).forEach(key => {
          if (SENSITIVE_FIELDS.some(s => key.toLowerCase().includes(s))) {
            obj[key] = '[REDACTED]';
          } else if (obj[key] && typeof obj[key] === 'object') {
            sanitizeObject(obj[key]);
          }
        });
      };
      
      if (Array.isArray(cleaned)) {
        cleaned.forEach(item => item && typeof item === 'object' && sanitizeObject(item));
      } else {
        sanitizeObject(cleaned);
      }
      
      return cleaned;
    };

    // Helper to parse dates flexibly
    const parseDate = (dateInput?: string): string | undefined => {
      if (!dateInput) return undefined;
      
      try {
        const date = new Date(dateInput);
        if (isNaN(date.getTime())) {
          throw new Error(`Invalid date format: ${dateInput}`);
        }
        return date.toISOString();
      } catch {
        return undefined;
      }
    };

    // Helper to simplify repository data for large responses
    const simplifyRepoData = (repo: any) => ({
      id: repo.id,
      name: repo.name,
      full_name: repo.full_name,
      owner: { login: repo.owner?.login, type: repo.owner?.type },
      private: repo.private,
      description: repo.description,
      url: repo.html_url,
      stars: repo.stargazers_count,
      forks: repo.forks_count,
      language: repo.language,
      updated_at: repo.updated_at,
      topics: (repo.topics || []).slice(0, 10) // Limit topics to prevent memory issues
    });

    // Helper to check if content is binary
    const isBinaryContent = (filename: string): boolean => {
      return BINARY_EXTENSIONS.test(filename);
    };

    // Helper to sanitize file paths
    const sanitizePath = (path: string): string => {
      return path.replace(/\.\.+/g, '.').replace(/\/+/g, '/').replace(/^\/+/, '');
    };

    // Helper to format tool responses consistently
    const formatToolResponse = (data: any, rateCheck?: { warning?: string }): { content: [{ type: "text"; text: string }] } => ({
      content: [{ 
        type: "text" as const, 
        text: JSON.stringify({
          ...data,
          ...(rateCheck?.warning ? { rate_limit_warning: rateCheck.warning } : {})
        })
      }]
    });

    // Helper to format error responses consistently
    const formatErrorResponse = (error: unknown, context?: string): { content: [{ type: "text"; text: string }] } => ({
      content: [{ type: "text" as const, text: handleError(error, context) }]
    });

    // Helper for retrying operations with exponential backoff
    const retryWithBackoff = async <T>(
      operation: () => Promise<T>,
      maxRetries: number = 3,
      context?: string
    ): Promise<T> => {
      let lastError: any;
      
      for (let attempt = 0; attempt < maxRetries; attempt++) {
        try {
          return await operation();
        } catch (error: any) {
          lastError = error;
          
          // Only retry on specific errors
          if (error.status === 409 || error.status === 502 || error.status === 503) {
            if (attempt < maxRetries - 1) {
              const delay = Math.min(100 * Math.pow(2, attempt), 1000);
              await new Promise(resolve => setTimeout(resolve, delay));
              continue;
            }
          }
          
          // Don't retry on other errors
          throw error;
        }
      }
      
      throw lastError;
    };

    // Helper to add timeout to operations
    const withTimeout = async <T>(
      operation: Promise<T>,
      timeoutMs: number = OPERATION_TIMEOUT,
      context?: string
    ): Promise<T> => {
      const timeout = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error(`Operation timeout after ${timeoutMs / 1000} seconds${context ? ` in ${context}` : ''}`)), timeoutMs)
      );
      
      return Promise.race([operation, timeout]);
    };

    // Helper to validate pagination
    const validatePagination = (page?: number): { isValid: boolean; error?: string } => {
      if (!page) return { isValid: true };
      
      if (page < 1) {
        return { isValid: false, error: "Page number must be at least 1" };
      }
      
      if (page > MAX_PAGES) {
        return { isValid: false, error: `Page ${page} exceeds maximum of ${MAX_PAGES}` };
      }
      
      return { isValid: true };
    };

    // ==========================================
    // USERS TOOLSET
    // ==========================================

    // get_authenticated_user - Get details of the authenticated user
    this.server.tool("get_authenticated_user", "Get details of the authenticated user", {}, async () => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        // Check rate limit
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.users.getAuthenticated(),
          OPERATION_TIMEOUT,
          'get_authenticated_user'
        );
        
        return formatToolResponse(sanitizeResponse(result.data), rateCheck);
      } catch (error) {
        return formatErrorResponse(error, "get_authenticated_user");
      }
    });

    // search_users - Search for GitHub users
    this.server.tool("search_users", "Search for GitHub users", {
      q: z.string().describe("Search query"),
      sort: z.enum(["followers", "repositories", "joined"]).optional().describe("Sort field"),
      order: z.enum(["asc", "desc"]).optional().describe("Sort order"),
      page: z.number().optional().describe("Page number"),
      perPage: perPageSchema.describe("Results per page (max 100)")
    }, async ({ q, sort, order, page, perPage }) => {
      // Validate pagination early
      const pageValidation = validatePagination(page);
      if (!pageValidation.isValid) {
        return formatToolResponse({ error: pageValidation.error });
      }

      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.search.users({ 
            q, 
            sort, 
            order, 
            page, 
            per_page: Math.min(perPage || 30, 100) 
          }),
          OPERATION_TIMEOUT,
          'search_users'
        );
        
        // Check for empty pages
        if (result.data.items.length === 0 && page && page > 1) {
          return formatToolResponse({ 
            message: "No more results",
            total_pages_checked: page,
            total_count: result.data.total_count
          });
        }
        
        const data = limitSearchResults(result.data, result.data.items.length);
        return formatToolResponse(data, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, "search_users");
      }
    });

    // ==========================================
    // ISSUES TOOLSET
    // ==========================================

    // get_issue - Gets the contents of an issue within a repository
    this.server.tool("get_issue", "Gets the contents of an issue within a repository", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      issueNumber: z.number().describe("Issue number")
    }, async ({ owner, repo, issueNumber }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.issues.get({ owner, repo, issue_number: issueNumber }),
          OPERATION_TIMEOUT,
          `get_issue ${owner}/${repo}#${issueNumber}`
        );
        
        return formatToolResponse(sanitizeResponse(result.data), rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `get_issue ${owner}/${repo}#${issueNumber}`);
      }
    });

    // get_issue_comments - Get comments for a GitHub issue
    this.server.tool("get_issue_comments", "Get comments for a GitHub issue", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      issueNumber: z.number().describe("Issue number"),
      page: z.number().optional().describe("Page number"),
      perPage: perPageSchema.describe("Results per page (max 100)")
    }, async ({ owner, repo, issueNumber, page, perPage }) => {
      // Validate pagination early
      const pageValidation = validatePagination(page);
      if (!pageValidation.isValid) {
        return formatToolResponse({ error: pageValidation.error });
      }

      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.issues.listComments({ 
            owner, 
            repo, 
            issue_number: issueNumber,
            page,
            per_page: Math.min(perPage || 30, 100)
          }),
          OPERATION_TIMEOUT,
          `get_issue_comments ${owner}/${repo}#${issueNumber}`
        );
        
        return formatToolResponse({
          comments: sanitizeResponse(result.data),
          count: result.data.length
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `get_issue_comments ${owner}/${repo}#${issueNumber}`);
      }
    });

    // create_issue - Create a new issue in a GitHub repository
    this.server.tool("create_issue", "Create a new issue in a GitHub repository", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      title: z.string().describe("Issue title"),
      body: z.string().optional().describe("Issue body content"),
      assignees: z.array(z.string()).optional().describe("Usernames to assign to this issue"),
      labels: z.array(z.string()).optional().describe("Labels to apply to this issue")
    }, async ({ owner, repo, title, body, assignees, labels }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          retryWithBackoff(
            () => octokit.rest.issues.create({ owner, repo, title, body, assignees, labels }),
            3,
            `create_issue ${owner}/${repo}`
          ),
          OPERATION_TIMEOUT,
          `create_issue ${owner}/${repo}`
        );
        
        return formatToolResponse({
          created: true,
          issue: sanitizeResponse(result.data)
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `create_issue ${owner}/${repo}`);
      }
    });

    // add_issue_comment - Add a comment to an issue
    this.server.tool("add_issue_comment", "Add a comment to an issue", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      issueNumber: z.number().describe("Issue number"),
      body: z.string().describe("Comment text")
    }, async ({ owner, repo, issueNumber, body }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          retryWithBackoff(
            () => octokit.rest.issues.createComment({ owner, repo, issue_number: issueNumber, body }),
            3,
            `add_issue_comment ${owner}/${repo}#${issueNumber}`
          ),
          OPERATION_TIMEOUT,
          `add_issue_comment ${owner}/${repo}#${issueNumber}`
        );
        
        return formatToolResponse({
          created: true,
          comment: sanitizeResponse(result.data)
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `add_issue_comment ${owner}/${repo}#${issueNumber}`);
      }
    });

    // list_issues - List and filter repository issues
    this.server.tool("list_issues", "List and filter repository issues", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      state: z.enum(["open", "closed", "all"]).optional().describe("Filter by state"),
      labels: z.array(z.string()).optional().describe("Labels to filter by"),
      sort: z.enum(["created", "updated", "comments"]).optional().describe("Sort by"),
      direction: z.enum(["asc", "desc"]).optional().describe("Sort direction"),
      since: z.string().optional().describe("Filter by date (ISO 8601 timestamp)"),
      page: z.number().optional().describe("Page number"),
      perPage: perPageSchema.describe("Results per page (max 100)")
    }, async ({ owner, repo, state, labels, sort, direction, since, page, perPage }) => {
      // Validate pagination early
      const pageValidation = validatePagination(page);
      if (!pageValidation.isValid) {
        return formatToolResponse({ error: pageValidation.error });
      }

      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.issues.listForRepo({ 
            owner, 
            repo, 
            state, 
            labels: labels?.join(','), // Convert array to comma-separated string
            sort, 
            direction, 
            since: parseDate(since), 
            page, 
            per_page: Math.min(perPage || 30, 100) 
          }),
          OPERATION_TIMEOUT,
          `list_issues ${owner}/${repo}`
        );
        
        // Early return for empty results
        if (!result.data.length) {
          return formatToolResponse({ issues: [], count: 0 }, rateCheck);
        }
        
        // Simplify issue data for large responses
        const simplifiedIssues = result.data.map(issue => ({
          number: issue.number,
          title: issue.title,
          state: issue.state,
          user: { login: issue.user?.login },
          labels: (issue.labels || []).slice(0, 10), // Limit labels
          assignees: issue.assignees?.slice(0, 10).map(a => ({ login: a.login })), // Limit assignees
          comments: issue.comments,
          created_at: issue.created_at,
          updated_at: issue.updated_at,
          html_url: issue.html_url
        }));
        
        return formatToolResponse({
          issues: simplifiedIssues,
          count: result.data.length
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `list_issues ${owner}/${repo}`);
      }
    });

    // update_issue - Update an existing issue in a GitHub repository
    this.server.tool("update_issue", "Update an existing issue in a GitHub repository", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      issueNumber: z.number().describe("Issue number to update"),
      title: z.string().optional().describe("New title"),
      body: z.string().optional().describe("New description"),
      state: z.enum(["open", "closed"]).optional().describe("New state"),
      labels: z.array(z.string()).optional().describe("New labels"),
      assignees: z.array(z.string()).optional().describe("New assignees"),
      milestone: z.number().optional().describe("New milestone number")
    }, async ({ owner, repo, issueNumber, title, body, state, labels, assignees, milestone }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        // Get original issue for diff
        let changes: Record<string, { from: any; to: any }> = {};
        try {
          const original = await octokit.rest.issues.get({ owner, repo, issue_number: issueNumber });
          
          if (title && title !== original.data.title) {
            changes['title'] = { from: original.data.title, to: title };
          }
          if (body && body !== original.data.body) {
            changes['body'] = { from: original.data.body?.substring(0, 100) + '...', to: body.substring(0, 100) + '...' };
          }
          if (state && state !== original.data.state) {
            changes['state'] = { from: original.data.state, to: state };
          }
        } catch {
          // If we can't get original, continue without diff
        }
        
        const result = await withTimeout(
          retryWithBackoff(
            () => octokit.rest.issues.update({ 
              owner, repo, issue_number: issueNumber, title, body, state, labels, assignees, milestone 
            }),
            3,
            `update_issue ${owner}/${repo}#${issueNumber}`
          ),
          OPERATION_TIMEOUT,
          `update_issue ${owner}/${repo}#${issueNumber}`
        );
        
        return formatToolResponse({
          updated: true,
          issue: sanitizeResponse(result.data),
          changes: Object.keys(changes).length > 0 ? changes : undefined
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `update_issue ${owner}/${repo}#${issueNumber}`);
      }
    });

    // search_issues - Search for issues and pull requests
    this.server.tool("search_issues", "Search for issues and pull requests", {
      query: z.string().describe("Search query"),
      sort: z.enum([
        "comments", 
        "reactions", 
        "reactions-+1", 
        "reactions--1", 
        "reactions-smile", 
        "reactions-thinking_face", 
        "reactions-heart", 
        "reactions-tada", 
        "interactions", 
        "created", 
        "updated"
      ]).optional().describe("Sort field"),
      order: z.enum(["asc", "desc"]).optional().describe("Sort order"),
      page: z.number().optional().describe("Page number"),
      perPage: perPageSchema.describe("Results per page (max 100)")
    }, async ({ query, sort, order, page, perPage }) => {
      // Validate pagination early
      const pageValidation = validatePagination(page);
      if (!pageValidation.isValid) {
        return formatToolResponse({ error: pageValidation.error });
      }

      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.search.issuesAndPullRequests({ 
            q: query, 
            sort, 
            order, 
            page, 
            per_page: Math.min(perPage || 30, 100) 
          }),
          OPERATION_TIMEOUT,
          'search_issues'
        );
        
        // Check for empty pages
        if (result.data.items.length === 0 && page && page > 1) {
          return formatToolResponse({ 
            message: "No more results",
            total_pages_checked: page,
            total_count: result.data.total_count
          });
        }
        
        // Simplify results for large responses
        const simplifiedItems = result.data.items.map(item => ({
          number: item.number,
          title: item.title,
          state: item.state,
          repository_url: item.repository_url,
          user: { login: item.user?.login },
          created_at: item.created_at,
          updated_at: item.updated_at,
          comments: item.comments,
          html_url: item.html_url,
          pull_request: item.pull_request ? true : false
        }));
        
        const data = limitSearchResults({
          ...result.data,
          items: simplifiedItems
        }, result.data.items.length);
        
        return formatToolResponse(data, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, "search_issues");
      }
    });

    // get_issue_events - Get events for an issue
    this.server.tool("get_issue_events", "Get events for an issue (labels, assignments, milestones, etc.)", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      issueNumber: z.number().describe("Issue number"),
      page: z.number().optional().describe("Page number"),
      perPage: perPageSchema.describe("Results per page (max 100)")
    }, async ({ owner, repo, issueNumber, page, perPage }) => {
      // Validate pagination early
      const pageValidation = validatePagination(page);
      if (!pageValidation.isValid) {
        return formatToolResponse({ error: pageValidation.error });
      }

      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.issues.listEvents({ 
            owner, 
            repo, 
            issue_number: issueNumber,
            page,
            per_page: Math.min(perPage || 30, 100)
          }),
          OPERATION_TIMEOUT,
          `get_issue_events ${owner}/${repo}#${issueNumber}`
        );
        
        // Simplify event data with proper type handling
        const events = result.data.map(event => {
          const anyEvent = event as any;
          const baseEvent = {
            id: event.id,
            event: event.event,
            actor: { login: event.actor?.login },
            created_at: event.created_at,
            ...(event.commit_id ? { commit_id: event.commit_id } : {})
          };

          // Add conditional properties based on what exists
          return {
            ...baseEvent,
            ...(anyEvent.label ? { label: anyEvent.label } : {}),
            ...(anyEvent.assignee ? { assignee: { login: anyEvent.assignee.login } } : {}),
            ...(anyEvent.milestone ? { milestone: { title: anyEvent.milestone.title } } : {}),
            ...(anyEvent.rename ? { rename: anyEvent.rename } : {})
          };
        });
        
        return formatToolResponse({
          events,
          count: events.length,
          issue: `${owner}/${repo}#${issueNumber}`
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `get_issue_events ${owner}/${repo}#${issueNumber}`);
      }
    });

    // get_issue_timeline - Get timeline events for an issue
    this.server.tool("get_issue_timeline", "Get timeline events for an issue (includes comments, commits, reviews, etc.)", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      issueNumber: z.number().describe("Issue number"),
      page: z.number().optional().describe("Page number"),
      perPage: perPageSchema.describe("Results per page (max 100)")
    }, async ({ owner, repo, issueNumber, page, perPage }) => {
      // Validate pagination early
      const pageValidation = validatePagination(page);
      if (!pageValidation.isValid) {
        return formatToolResponse({ error: pageValidation.error });
      }

      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.issues.listEventsForTimeline({ 
            owner, 
            repo, 
            issue_number: issueNumber,
            page,
            per_page: Math.min(perPage || 30, 100)
          }),
          OPERATION_TIMEOUT,
          `get_issue_timeline ${owner}/${repo}#${issueNumber}`
        );
        
        // Simplify timeline data with proper type handling
        const timeline = result.data.map(item => {
          const anyItem = item as any;
          const base = {
            id: anyItem.id,
            event: anyItem.event,
            created_at: anyItem.created_at,
            actor: anyItem.actor ? { login: anyItem.actor.login } : undefined
          };
          
          // Add event-specific data
          switch (anyItem.event) {
            case 'commented':
              return { ...base, body: anyItem.body?.substring(0, 200) + '...' };
            case 'committed':
              return { ...base, sha: anyItem.sha, message: anyItem.message };
            case 'reviewed':
              return { ...base, state: anyItem.state, body: anyItem.body?.substring(0, 200) + '...' };
            case 'labeled':
            case 'unlabeled':
              return { ...base, label: anyItem.label };
            case 'assigned':
            case 'unassigned':
              return { ...base, assignee: anyItem.assignee ? { login: anyItem.assignee.login } : undefined };
            case 'milestoned':
            case 'demilestoned':
              return { ...base, milestone: anyItem.milestone ? { title: anyItem.milestone.title } : undefined };
            case 'renamed':
              return { ...base, rename: anyItem.rename };
            case 'cross-referenced':
              return { ...base, source: anyItem.source };
            default:
              return base;
          }
        });
        
        return formatToolResponse({
          timeline,
          count: timeline.length,
          issue: `${owner}/${repo}#${issueNumber}`
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `get_issue_timeline ${owner}/${repo}#${issueNumber}`);
      }
    });

    // ==========================================
    // PULL REQUESTS TOOLSET
    // ==========================================

    // get_pull_request - Get details of a specific pull request
    this.server.tool("get_pull_request", "Get details of a specific pull request", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      pullNumber: z.number().describe("Pull request number")
    }, async ({ owner, repo, pullNumber }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.pulls.get({ owner, repo, pull_number: pullNumber }),
          OPERATION_TIMEOUT,
          `get_pull_request ${owner}/${repo}#${pullNumber}`
        );
        
        return formatToolResponse(sanitizeResponse(result.data), rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `get_pull_request ${owner}/${repo}#${pullNumber}`);
      }
    });

    // list_pull_requests - List and filter repository pull requests
    this.server.tool("list_pull_requests", "List and filter repository pull requests", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      state: z.enum(["open", "closed", "all"]).optional().describe("PR state"),
      sort: z.enum(["created", "updated", "popularity"]).optional().describe("Sort field"),
      direction: z.enum(["asc", "desc"]).optional().describe("Sort direction"),
      perPage: perPageSchema.describe("Results per page (max 100)"),
      page: z.number().optional().describe("Page number")
    }, async ({ owner, repo, state, sort, direction, perPage, page }) => {
      // Validate pagination early
      const pageValidation = validatePagination(page);
      if (!pageValidation.isValid) {
        return formatToolResponse({ error: pageValidation.error });
      }

      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.pulls.list({ 
            owner, 
            repo, 
            state, 
            sort, 
            direction, 
            per_page: Math.min(perPage || 30, 100), 
            page 
          }),
          OPERATION_TIMEOUT,
          `list_pull_requests ${owner}/${repo}`
        );
        
        // Simplify PR data for large responses
        const simplifiedPRs = result.data.map(pr => ({
          number: pr.number,
          title: pr.title,
          state: pr.state,
          user: { login: pr.user?.login },
          created_at: pr.created_at,
          updated_at: pr.updated_at,
          merged_at: pr.merged_at,
          head: { ref: pr.head.ref, sha: pr.head.sha },
          base: { ref: pr.base.ref },
          html_url: pr.html_url,
          draft: pr.draft
        }));
        
        return formatToolResponse({
          pull_requests: simplifiedPRs,
          count: result.data.length
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `list_pull_requests ${owner}/${repo}`);
      }
    });

    // merge_pull_request - Merge a pull request
    this.server.tool("merge_pull_request", "Merge a pull request", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      pullNumber: z.number().describe("Pull request number"),
      commitTitle: z.string().optional().describe("Title for the merge commit"),
      commitMessage: z.string().optional().describe("Message for the merge commit"),
      mergeMethod: z.enum(["merge", "squash", "rebase"]).optional().describe("Merge method")
    }, async ({ owner, repo, pullNumber, commitTitle, commitMessage, mergeMethod }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        // Check if PR is ready to merge
        const prStatus = await octokit.rest.pulls.get({ owner, repo, pull_number: pullNumber });
        if (!prStatus.data.mergeable) {
          return formatToolResponse({ 
            error: "Pull request is not mergeable",
            mergeable_state: prStatus.data.mergeable_state,
            details: "The pull request may have conflicts or failing checks"
          });
        }
        
        const result = await withTimeout(
          retryWithBackoff(
            () => octokit.rest.pulls.merge({ 
              owner, repo, pull_number: pullNumber, commit_title: commitTitle, commit_message: commitMessage, merge_method: mergeMethod 
            }),
            3,
            `merge_pull_request ${owner}/${repo}#${pullNumber}`
          ),
          OPERATION_TIMEOUT,
          `merge_pull_request ${owner}/${repo}#${pullNumber}`
        );
        
        return formatToolResponse({
          ...result.data,
          merged: true
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `merge_pull_request ${owner}/${repo}#${pullNumber}`);
      }
    });

    // get_pull_request_files - Get the list of files changed in a pull request
    this.server.tool("get_pull_request_files", "Get the list of files changed in a pull request", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      pullNumber: z.number().describe("Pull request number"),
      page: z.number().optional().describe("Page number"),
      perPage: perPageSchema.describe("Results per page (max 100)")
    }, async ({ owner, repo, pullNumber, page, perPage }) => {
      // Validate pagination early
      const pageValidation = validatePagination(page);
      if (!pageValidation.isValid) {
        return formatToolResponse({ error: pageValidation.error });
      }

      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.pulls.listFiles({ 
            owner, 
            repo, 
            pull_number: pullNumber,
            page,
            per_page: Math.min(perPage || 30, 100)
          }),
          OPERATION_TIMEOUT,
          `get_pull_request_files ${owner}/${repo}#${pullNumber}`
        );
        
        // Simplify file data
        const files = result.data.map(file => ({
          filename: file.filename,
          status: file.status,
          additions: file.additions,
          deletions: file.deletions,
          changes: file.changes,
          patch: file.patch ? file.patch.substring(0, 500) + (file.patch.length > 500 ? '...' : '') : undefined
        }));
        
        return formatToolResponse({
          files,
          count: result.data.length,
          total_additions: files.reduce((sum, f) => sum + f.additions, 0),
          total_deletions: files.reduce((sum, f) => sum + f.deletions, 0)
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `get_pull_request_files ${owner}/${repo}#${pullNumber}`);
      }
    });

    // get_pull_request_status - Get the combined status of all status checks for a pull request
    this.server.tool("get_pull_request_status", "Get the combined status of all status checks for a pull request", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      pullNumber: z.number().describe("Pull request number")
    }, async ({ owner, repo, pullNumber }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        // Fixed: Use direct ref instead of double API call
        try {
          const result = await withTimeout(
            octokit.rest.repos.getCombinedStatusForRef({ 
              owner, 
              repo, 
              ref: `pull/${pullNumber}/head` 
            }),
            OPERATION_TIMEOUT,
            `get_pull_request_status ${owner}/${repo}#${pullNumber}`
          );
          
          return formatToolResponse(result.data, rateCheck);
        } catch (error) {
          // Fallback to getting PR first if direct ref fails
          const pr = await octokit.rest.pulls.get({ owner, repo, pull_number: pullNumber });
          const result = await octokit.rest.repos.getCombinedStatusForRef({ 
            owner, 
            repo, 
            ref: pr.data.head.sha 
          });
          
          return formatToolResponse(result.data, rateCheck);
        }
      } catch (error) {
        return formatErrorResponse(error, `get_pull_request_status ${owner}/${repo}#${pullNumber}`);
      }
    });

    // update_pull_request_branch - Update a pull request branch with the latest changes from the base branch
    this.server.tool("update_pull_request_branch", "Update a pull request branch with the latest changes from the base branch", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      pullNumber: z.number().describe("Pull request number"),
      expectedHeadSha: z.string().optional().describe("The expected SHA of the pull request's HEAD ref")
    }, async ({ owner, repo, pullNumber, expectedHeadSha }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          retryWithBackoff(
            () => octokit.rest.pulls.updateBranch({ 
              owner, repo, pull_number: pullNumber, expected_head_sha: expectedHeadSha 
            }),
            3,
            `update_pull_request_branch ${owner}/${repo}#${pullNumber}`
          ),
          OPERATION_TIMEOUT,
          `update_pull_request_branch ${owner}/${repo}#${pullNumber}`
        );
        
        return formatToolResponse({
          updated: true,
          ...result.data
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `update_pull_request_branch ${owner}/${repo}#${pullNumber}`);
      }
    });

    // create_pull_request - Create a new pull request
    this.server.tool("create_pull_request", "Create a new pull request", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      title: z.string().describe("PR title"),
      body: z.string().optional().describe("PR description"),
      head: githubBranchNameSchema.describe("Branch containing changes"),
      base: githubBranchNameSchema.describe("Branch to merge into"),
      draft: z.boolean().optional().describe("Create as draft PR"),
      maintainerCanModify: z.boolean().optional().describe("Allow maintainer edits")
    }, async ({ owner, repo, title, body, head, base, draft, maintainerCanModify }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        // Check if base branch is protected
        try {
          const branchInfo = await octokit.rest.repos.getBranch({ owner, repo, branch: base });
          if (branchInfo.data.protected) {
            const protection = await octokit.rest.repos.getBranchProtection({ owner, repo, branch: base }).catch(() => null);
            if (protection) {
              return formatToolResponse({
                warning: "Target branch is protected",
                protection_rules: {
                  required_reviews: protection.data.required_pull_request_reviews,
                  required_status_checks: protection.data.required_status_checks,
                  enforce_admins: protection.data.enforce_admins?.enabled
                },
                message: "Pull request will be created but may require reviews or status checks before merging"
              });
            }
          }
        } catch {
          // Continue if protection check fails
        }
        
        const result = await withTimeout(
          retryWithBackoff(
            () => octokit.rest.pulls.create({ 
              owner, repo, title, body, head, base, draft, maintainer_can_modify: maintainerCanModify 
            }),
            3,
            `create_pull_request ${owner}/${repo}`
          ),
          OPERATION_TIMEOUT,
          `create_pull_request ${owner}/${repo}`
        );
        
        return formatToolResponse({
          created: true,
          pull_request: sanitizeResponse(result.data)
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `create_pull_request ${owner}/${repo}`);
      }
    });

    // get_pull_request_comments - Get the review comments on a pull request
    this.server.tool("get_pull_request_comments", "Get the review comments on a pull request", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      pullNumber: z.number().describe("Pull request number"),
      page: z.number().optional().describe("Page number"),
      perPage: perPageSchema.describe("Results per page (max 100)")
    }, async ({ owner, repo, pullNumber, page, perPage }) => {
      // Validate pagination early
      const pageValidation = validatePagination(page);
      if (!pageValidation.isValid) {
        return formatToolResponse({ error: pageValidation.error });
      }

      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.pulls.listReviewComments({ 
            owner, 
            repo, 
            pull_number: pullNumber,
            page,
            per_page: Math.min(perPage || 30, 100)
          }),
          OPERATION_TIMEOUT,
          `get_pull_request_comments ${owner}/${repo}#${pullNumber}`
        );
        
        return formatToolResponse({
          comments: sanitizeResponse(result.data),
          count: result.data.length
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `get_pull_request_comments ${owner}/${repo}#${pullNumber}`);
      }
    });

    // get_pull_request_reviews - Get the reviews on a pull request
    this.server.tool("get_pull_request_reviews", "Get the reviews on a pull request", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      pullNumber: z.number().describe("Pull request number"),
      page: z.number().optional().describe("Page number"),
      perPage: perPageSchema.describe("Results per page (max 100)")
    }, async ({ owner, repo, pullNumber, page, perPage }) => {
      // Validate pagination early
      const pageValidation = validatePagination(page);
      if (!pageValidation.isValid) {
        return formatToolResponse({ error: pageValidation.error });
      }

      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.pulls.listReviews({ 
            owner, 
            repo, 
            pull_number: pullNumber,
            page,
            per_page: Math.min(perPage || 30, 100)
          }),
          OPERATION_TIMEOUT,
          `get_pull_request_reviews ${owner}/${repo}#${pullNumber}`
        );
        
        return formatToolResponse({
          reviews: sanitizeResponse(result.data),
          count: result.data.length,
          approved_count: result.data.filter(r => r.state === 'APPROVED').length,
          changes_requested_count: result.data.filter(r => r.state === 'CHANGES_REQUESTED').length
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `get_pull_request_reviews ${owner}/${repo}#${pullNumber}`);
      }
    });

    // create_pull_request_review - Create a review on a pull request
    this.server.tool("create_pull_request_review", "Create a review on a pull request", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      pullNumber: z.number().describe("Pull request number"),
      body: z.string().optional().describe("Review comment text"),
      event: z.enum(["APPROVE", "REQUEST_CHANGES", "COMMENT"]).describe("Review action"),
      commitId: z.string().optional().describe("SHA of commit to review")
    }, async ({ owner, repo, pullNumber, body, event, commitId }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          retryWithBackoff(
            () => octokit.rest.pulls.createReview({ 
              owner, repo, pull_number: pullNumber, body, event, commit_id: commitId 
            }),
            3,
            `create_pull_request_review ${owner}/${repo}#${pullNumber}`
          ),
          OPERATION_TIMEOUT,
          `create_pull_request_review ${owner}/${repo}#${pullNumber}`
        );
        
        return formatToolResponse({
          created: true,
          review: sanitizeResponse(result.data)
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `create_pull_request_review ${owner}/${repo}#${pullNumber}`);
      }
    });

    // add_pull_request_review_comment - Add a review comment to a pull request
    this.server.tool("add_pull_request_review_comment", "Add a review comment to a pull request or reply to an existing comment", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      pullNumber: z.number().describe("Pull request number"),
      body: z.string().describe("The text of the review comment"),
      commitId: z.string().describe("The SHA of the commit to comment on"),
      path: z.string().describe("The relative path to the file that necessitates a comment"),
      line: z.number().optional().describe("The line of the blob in the pull request diff that the comment applies to"),
      side: z.enum(["LEFT", "RIGHT"]).optional().describe("The side of the diff to comment on"),
      startLine: z.number().optional().describe("For multi-line comments, the first line of the range"),
      startSide: z.enum(["LEFT", "RIGHT"]).optional().describe("For multi-line comments, the starting side of the diff"),
      inReplyTo: z.number().optional().describe("The ID of the review comment to reply to")
    }, async ({ owner, repo, pullNumber, body, commitId, path, line, side, startLine, startSide, inReplyTo }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          retryWithBackoff(
            () => octokit.rest.pulls.createReviewComment({ 
              owner, repo, pull_number: pullNumber, body, commit_id: commitId, path, line, side, 
              start_line: startLine, start_side: startSide, in_reply_to: inReplyTo 
            }),
            3,
            `add_pull_request_review_comment ${owner}/${repo}#${pullNumber}`
          ),
          OPERATION_TIMEOUT,
          `add_pull_request_review_comment ${owner}/${repo}#${pullNumber}`
        );
        
        return formatToolResponse({
          created: true,
          comment: sanitizeResponse(result.data)
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `add_pull_request_review_comment ${owner}/${repo}#${pullNumber}`);
      }
    });

    // update_pull_request - Update an existing pull request
    this.server.tool("update_pull_request", "Update an existing pull request in a GitHub repository", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      pullNumber: z.number().describe("Pull request number to update"),
      title: z.string().optional().describe("New title"),
      body: z.string().optional().describe("New description"),
      state: z.enum(["open", "closed"]).optional().describe("New state"),
      base: githubBranchNameSchema.optional().describe("New base branch name"),
      maintainerCanModify: z.boolean().optional().describe("Allow maintainer edits")
    }, async ({ owner, repo, pullNumber, title, body, state, base, maintainerCanModify }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        // Get original PR for diff
        let changes: Record<string, { from: any; to: any }> = {};
        try {
          const original = await octokit.rest.pulls.get({ owner, repo, pull_number: pullNumber });
          
          if (title && title !== original.data.title) {
            changes['title'] = { from: original.data.title, to: title };
          }
          if (body && body !== original.data.body) {
            changes['body'] = { from: original.data.body?.substring(0, 100) + '...', to: body.substring(0, 100) + '...' };
          }
          if (state && state !== original.data.state) {
            changes['state'] = { from: original.data.state, to: state };
          }
          if (base && base !== original.data.base.ref) {
            changes['base'] = { from: original.data.base.ref, to: base };
          }
        } catch {
          // Continue without diff if we can't get original
        }
        
        const result = await withTimeout(
          retryWithBackoff(
            () => octokit.rest.pulls.update({ 
              owner, repo, pull_number: pullNumber, title, body, state, base, maintainer_can_modify: maintainerCanModify 
            }),
            3,
            `update_pull_request ${owner}/${repo}#${pullNumber}`
          ),
          OPERATION_TIMEOUT,
          `update_pull_request ${owner}/${repo}#${pullNumber}`
        );
        
        return formatToolResponse({
          updated: true,
          pull_request: sanitizeResponse(result.data),
          changes: Object.keys(changes).length > 0 ? changes : undefined
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `update_pull_request ${owner}/${repo}#${pullNumber}`);
      }
    });

    // request_copilot_review - Request a review from GitHub Copilot (Experimental)
    this.server.tool("request_copilot_review", "Request a review from GitHub Copilot for a pull request (Experimental feature)", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      pullNumber: z.number().describe("Pull request number")
    }, async ({ owner, repo, pullNumber }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        // Note: This is an experimental feature and the API endpoint might change
        // Currently using the review request API with 'github-copilot' as reviewer
        try {
          const result = await withTimeout(
            octokit.rest.pulls.requestReviewers({
              owner,
              repo,
              pull_number: pullNumber,
              reviewers: ['github-copilot']
            }),
            OPERATION_TIMEOUT,
            `request_copilot_review ${owner}/${repo}#${pullNumber}`
          );
          
          return formatToolResponse({
            requested: true,
            message: "Copilot review requested successfully",
            pull_request: `${owner}/${repo}#${pullNumber}`,
            reviewers: result.data.requested_reviewers
          }, rateCheck);
        } catch (error: any) {
          // Handle specific Copilot-related errors
          if (error.status === 422 && error.message?.includes('copilot')) {
            return formatToolResponse({
              error: "Copilot review not available",
              message: "GitHub Copilot reviews may not be available for this repository. This is an experimental feature.",
              details: error.message
            });
          }
          throw error;
        }
      } catch (error) {
        return formatErrorResponse(error, `request_copilot_review ${owner}/${repo}#${pullNumber}`);
      }
    });

    // ==========================================
    // REPOSITORIES TOOLSET
    // ==========================================

    // get_file_contents - Get contents of a file or directory (FIXED: decodes base64)
    this.server.tool("get_file_contents", "Get contents of a file or directory", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      path: githubPathSchema.describe("File path"),
      ref: z.string().optional().describe("Git reference")
    }, async ({ owner, repo, path, ref }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const sanitizedPath = sanitizePath(path);
        const result = await withTimeout(
          octokit.rest.repos.getContent({ owner, repo, path: sanitizedPath, ref }),
          OPERATION_TIMEOUT,
          `get_file_contents ${owner}/${repo}/${path}`
        );
        
        // Handle single file with base64 content
        if (!Array.isArray(result.data) && 'content' in result.data && result.data.type === 'file') {
          // Check if file is binary
          const isBinary = isBinaryContent(result.data.name);
          
          if (isBinary) {
            return formatToolResponse({
              name: result.data.name,
              path: result.data.path,
              size: result.data.size,
              type: result.data.type,
              sha: result.data.sha,
              content: "[Binary file - base64 encoded]",
              content_base64: result.data.content,
              isBinary: true,
              download_url: result.data.download_url
            }, rateCheck);
          }
          
          // Decode text content
          const decodedContent = decodeBase64(result.data.content);
          return formatToolResponse({
            name: result.data.name,
            path: result.data.path,
            size: result.data.size,
            type: result.data.type,
            sha: result.data.sha,
            content: decodedContent, // Human readable content
            content_base64: result.data.content, // Keep original base64 if needed
            download_url: result.data.download_url
          }, rateCheck);
        }
        
        // For directories, simplify the output
        if (Array.isArray(result.data)) {
          const files = result.data.map(item => ({
            name: item.name,
            path: item.path,
            type: item.type,
            size: item.size,
            sha: item.sha
          }));
          
          return formatToolResponse({
            type: "directory",
            files,
            count: files.length
          }, rateCheck);
        }
        
        // For other types, return as-is
        return formatToolResponse(result.data, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `get_file_contents ${owner}/${repo}/${path}`);
      }
    });

    // create_or_update_file - Create or update a single file in a repository
    this.server.tool("create_or_update_file", "Create or update a single file in a repository", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      path: githubPathSchema.describe("File path"),
      message: z.string().describe("Commit message"),
      content: z.string().describe("File content"),
      branch: githubBranchNameSchema.optional().describe("Branch name"),
      sha: z.string().optional().describe("File SHA if updating")
    }, async ({ owner, repo, path, message, content, branch, sha }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const sanitizedPath = sanitizePath(path);
        
        // Check file size
        const contentBytes = new TextEncoder().encode(content).length;
        if (contentBytes > FILE_SIZE_LIMIT) {
          return formatToolResponse({
            error: "File too large",
            message: `File size (${contentBytes} bytes) exceeds GitHub API limit of ${FILE_SIZE_LIMIT} bytes. Use push_files for large files.`,
            size: contentBytes,
            limit: FILE_SIZE_LIMIT
          });
        }
        
        // Retry logic for SHA conflicts
        const performUpdate = async (currentSha?: string) => {
          const encodedContent = encodeContent(content);
          return octokit.rest.repos.createOrUpdateFileContents({ 
            owner, repo, path: sanitizedPath, message, content: encodedContent, branch, sha: currentSha 
          });
        };
        
        let result;
        
        // If no SHA provided, try to get current SHA for updates
        if (!sha) {
          try {
            const currentFile = await octokit.rest.repos.getContent({ owner, repo, path: sanitizedPath, ref: branch });
            if (!Array.isArray(currentFile.data) && 'sha' in currentFile.data) {
              sha = currentFile.data.sha;
            }
          } catch {
            // File doesn't exist, will create new
          }
        }
        
        // Perform update with retry logic
        result = await withTimeout(
          retryWithBackoff(
            () => performUpdate(sha),
            3,
            `create_or_update_file ${owner}/${repo}/${path}`
          ),
          OPERATION_TIMEOUT,
          `create_or_update_file ${owner}/${repo}/${path}`
        );
        
        return formatToolResponse({
          created: !sha,
          updated: !!sha,
          commit: result.data.commit,
          content: {
            name: result.data.content?.name,
            path: result.data.content?.path,
            sha: result.data.content?.sha,
            size: contentBytes
          }
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `create_or_update_file ${owner}/${repo}/${path}`);
      }
    });

    // push_files - Push multiple files in a single commit
    this.server.tool("push_files", "Push multiple files in a single commit", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      branch: githubBranchNameSchema.describe("Branch to push to"),
      files: z.array(z.object({
        path: z.string().describe("File path"),
        content: z.string().describe("File content")
      })).describe("Files to push, each with path and content"),
      message: z.string().describe("Commit message")
    }, async ({ owner, repo, branch, files, message }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        // Wrap entire operation with timeout
        const result = await withTimeout(
          (async () => {
            // Get the latest commit SHA for the branch
            const branchData = await octokit.rest.repos.getBranch({ owner, repo, branch });
            const latestCommitSha = branchData.data.commit.sha;
            
            // Get the tree for the latest commit
            const latestCommit = await octokit.rest.git.getCommit({ owner, repo, commit_sha: latestCommitSha });
            
            // Process files in batches with detailed error tracking
            const results = {
              succeeded: [] as Array<{ path: string; sha: string }>,
              failed: [] as Array<{ path: string; error: string; index: number }>,
              total: files.length
            };
            
            type TreeItem = {
              path: string;
              mode: '100644';
              type: 'blob';
              sha: string;
            };
            
            const tree: TreeItem[] = [];
            
            // Process files in batches to avoid rate limiting
            for (let i = 0; i < files.length; i += BATCH_SIZE) {
              const batch = files.slice(i, i + BATCH_SIZE);
              
              const batchResults = await Promise.allSettled(
                batch.map(async (file, batchIndex) => {
                  const index = i + batchIndex;
                  const sanitizedPath = sanitizePath(file.path);
                  
                  try {
                    // Check if file is too large for standard API
                    const contentBytes = new TextEncoder().encode(file.content).length;
                    if (contentBytes > FILE_SIZE_LIMIT) {
                      throw new Error(`File size (${contentBytes} bytes) exceeds limit of ${FILE_SIZE_LIMIT} bytes`);
                    }
                    
                    const blob = await octokit.rest.git.createBlob({
                      owner, repo,
                      content: encodeContent(file.content),
                      encoding: 'base64'
                    });
                    
                    results.succeeded.push({ path: sanitizedPath, sha: blob.data.sha });
                    
                    return {
                      path: sanitizedPath,
                      mode: '100644' as const,
                      type: 'blob' as const,
                      sha: blob.data.sha
                    } as TreeItem;
                  } catch (error) {
                    const errorMessage = error instanceof Error ? error.message : String(error);
                    results.failed.push({ 
                      path: sanitizedPath, 
                      error: errorMessage,
                      index 
                    });
                    return null;
                  }
                })
              );
              
              // Add successful blobs to tree
              batchResults.forEach(result => {
                if (result.status === 'fulfilled' && result.value) {
                  tree.push(result.value);
                }
              });
              
              // Rate limit pause between batches
              if (i + BATCH_SIZE < files.length) {
                await new Promise(resolve => setTimeout(resolve, 100));
              }
            }
            
            // If no files succeeded, return error
            if (results.succeeded.length === 0) {
              return {
                error: "All files failed to process",
                results
              };
            }
            
            // Create a new tree with successful files
            const newTree = await octokit.rest.git.createTree({
              owner, repo,
              base_tree: latestCommit.data.tree.sha,
              tree
            });
            
            // Create a new commit
            const newCommit = await octokit.rest.git.createCommit({
              owner, repo,
              message,
              tree: newTree.data.sha,
              parents: [latestCommitSha]
            });
            
            // Update the branch reference
            const updateResult = await octokit.rest.git.updateRef({
              owner, repo,
              ref: `heads/${branch}`,
              sha: newCommit.data.sha
            });
            
            return {
              success: true,
              commit: {
                sha: newCommit.data.sha,
                message: newCommit.data.message,
                url: newCommit.data.html_url
              },
              results,
              branch_updated: updateResult.data.ref
            };
          })(),
          OPERATION_TIMEOUT,
          `push_files ${owner}/${repo} to ${branch}`
        );
        
        return formatToolResponse(result, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `push_files ${owner}/${repo} to ${branch}`);
      }
    });

    // list_branches - List branches in a GitHub repository
    this.server.tool("list_branches", "List branches in a GitHub repository", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      page: z.number().optional().describe("Page number"),
      perPage: perPageSchema.describe("Results per page (max 100)")
    }, async ({ owner, repo, page, perPage }) => {
      // Validate pagination early
      const pageValidation = validatePagination(page);
      if (!pageValidation.isValid) {
        return formatToolResponse({ error: pageValidation.error });
      }

      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.repos.listBranches({ 
            owner, 
            repo, 
            page, 
            per_page: Math.min(perPage || 30, 100) 
          }),
          OPERATION_TIMEOUT,
          `list_branches ${owner}/${repo}`
        );
        
        // Simplify branch data
        const branches = result.data.map(branch => ({
          name: branch.name,
          commit: {
            sha: branch.commit.sha,
            url: branch.commit.url
          },
          protected: branch.protected
        }));
        
        return formatToolResponse({
          branches,
          count: branches.length
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `list_branches ${owner}/${repo}`);
      }
    });

    // search_repositories - Search for GitHub repositories
    this.server.tool("search_repositories", "Search for GitHub repositories", {
      query: z.string().describe("Search query"),
      sort: z.enum(["stars", "forks", "help-wanted-issues", "updated"]).optional().describe("Sort field"),
      order: z.enum(["asc", "desc"]).optional().describe("Sort order"),
      page: z.number().optional().describe("Page number"),
      perPage: perPageSchema.describe("Results per page (max 100)")
    }, async ({ query, sort, order, page, perPage }) => {
      // Validate pagination early
      const pageValidation = validatePagination(page);
      if (!pageValidation.isValid) {
        return formatToolResponse({ error: pageValidation.error });
      }

      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.search.repos({ 
            q: query, 
            sort, 
            order, 
            page, 
            per_page: Math.min(perPage || 30, 100) 
          }),
          OPERATION_TIMEOUT,
          'search_repositories'
        );
        
        // Check for empty pages
        if (result.data.items.length === 0 && page && page > 1) {
          return formatToolResponse({ 
            message: "No more results",
            total_pages_checked: page,
            total_count: result.data.total_count
          });
        }
        
        // Simplify repository data for large responses
        const simplifiedRepos = result.data.items.map(simplifyRepoData);
        
        const data = limitSearchResults({
          total_count: result.data.total_count,
          incomplete_results: result.data.incomplete_results,
          items: simplifiedRepos
        }, result.data.items.length);
        
        return formatToolResponse(data, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, "search_repositories");
      }
    });

    // create_repository - Create a new GitHub repository
    this.server.tool("create_repository", "Create a new GitHub repository", {
      name: githubRepoNameSchema.describe("Repository name"),
      description: z.string().optional().describe("Repository description"),
      private: z.boolean().optional().describe("Whether the repository is private"),
      autoInit: z.boolean().optional().describe("Auto-initialize with README")
    }, async ({ name, description, private: isPrivate, autoInit }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          retryWithBackoff(
            () => octokit.rest.repos.createForAuthenticatedUser({ 
              name, description, private: isPrivate, auto_init: autoInit 
            }),
            3,
            `create_repository ${name}`
          ),
          OPERATION_TIMEOUT,
          `create_repository ${name}`
        );
        
        return formatToolResponse({
          created: true,
          repository: simplifyRepoData(result.data)
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `create_repository ${name}`);
      }
    });

    // fork_repository - Fork a repository
    this.server.tool("fork_repository", "Fork a repository", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      organization: z.string().optional().describe("Target organization name")
    }, async ({ owner, repo, organization }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          retryWithBackoff(
            () => octokit.rest.repos.createFork({ owner, repo, organization }),
            3,
            `fork_repository ${owner}/${repo}`
          ),
          OPERATION_TIMEOUT,
          `fork_repository ${owner}/${repo}`
        );
        
        return formatToolResponse({
          forked: true,
          repository: simplifyRepoData(result.data),
          parent: {
            full_name: `${owner}/${repo}`,
            html_url: `https://github.com/${owner}/${repo}`
          }
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `fork_repository ${owner}/${repo}`);
      }
    });

    // create_branch - Create a new branch
    this.server.tool("create_branch", "Create a new branch", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      branch: githubBranchNameSchema.describe("New branch name"),
      sha: z.string().describe("SHA to create branch from")
    }, async ({ owner, repo, branch, sha }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          retryWithBackoff(
            () => octokit.rest.git.createRef({ 
              owner, repo, ref: `refs/heads/${branch}`, sha 
            }),
            3,
            `create_branch ${owner}/${repo}/${branch}`
          ),
          OPERATION_TIMEOUT,
          `create_branch ${owner}/${repo}/${branch}`
        );
        
        return formatToolResponse({
          created: true,
          branch: {
            name: branch,
            ref: result.data.ref,
            sha: result.data.object.sha,
            url: result.data.url
          }
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `create_branch ${owner}/${repo}/${branch}`);
      }
    });

    // list_commits - Get a list of commits of a branch in a repository
    this.server.tool("list_commits", "Get a list of commits of a branch in a repository", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      sha: z.string().optional().describe("Branch name, tag, or commit SHA"),
      path: z.string().optional().describe("Only commits containing this file path"),
      page: z.number().optional().describe("Page number"),
      perPage: perPageSchema.describe("Results per page (max 100)")
    }, async ({ owner, repo, sha, path, page, perPage }) => {
      // Validate pagination early
      const pageValidation = validatePagination(page);
      if (!pageValidation.isValid) {
        return formatToolResponse({ error: pageValidation.error });
      }

      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.repos.listCommits({ 
            owner, 
            repo, 
            sha, 
            path, 
            page, 
            per_page: Math.min(perPage || 30, 100) 
          }),
          OPERATION_TIMEOUT,
          `list_commits ${owner}/${repo}`
        );
        
        // Simplify commit data
        const commits = result.data.map(commit => ({
          sha: commit.sha,
          message: commit.commit.message,
          author: {
            name: commit.commit.author?.name,
            email: commit.commit.author?.email,
            date: commit.commit.author?.date,
            login: commit.author?.login
          },
          committer: {
            name: commit.commit.committer?.name,
            email: commit.commit.committer?.email,
            date: commit.commit.committer?.date,
            login: commit.committer?.login
          },
          url: commit.html_url
        }));
        
        return formatToolResponse({
          commits,
          count: commits.length
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `list_commits ${owner}/${repo}`);
      }
    });

    // get_commit - Get details for a commit from a repository
    this.server.tool("get_commit", "Get details for a commit from a repository", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      sha: z.string().describe("Commit SHA, branch name, or tag name")
    }, async ({ owner, repo, sha }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.repos.getCommit({ owner, repo, ref: sha }),
          OPERATION_TIMEOUT,
          `get_commit ${owner}/${repo}@${sha}`
        );
        
        // Simplify commit data
        const simplifiedCommit = {
          sha: result.data.sha,
          message: result.data.commit.message,
          author: result.data.commit.author,
          committer: result.data.commit.committer,
          stats: result.data.stats,
          files: result.data.files?.map(file => ({
            filename: file.filename,
            status: file.status,
            additions: file.additions,
            deletions: file.deletions,
            changes: file.changes,
            patch: file.patch ? file.patch.substring(0, 500) + (file.patch.length > 500 ? '...' : '') : undefined
          })),
          parents: result.data.parents.map(p => ({ sha: p.sha })),
          url: result.data.html_url
        };
        
        return formatToolResponse({
          commit: simplifiedCommit
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `get_commit ${owner}/${repo}@${sha}`);
      }
    });

    // search_code - Search for code across GitHub repositories
    this.server.tool("search_code", "Search for code across GitHub repositories", {
      query: z.string().describe("Search query"),
      sort: z.enum(["indexed"]).optional().describe("Sort field"),
      order: z.enum(["asc", "desc"]).optional().describe("Sort order"),
      page: z.number().optional().describe("Page number"),
      perPage: perPageSchema.describe("Results per page (max 100)")
    }, async ({ query, sort, order, page, perPage }) => {
      // Validate pagination early
      const pageValidation = validatePagination(page);
      if (!pageValidation.isValid) {
        return formatToolResponse({ error: pageValidation.error });
      }

      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.search.code({ 
            q: query, 
            sort, 
            order, 
            page, 
            per_page: Math.min(perPage || 30, 100) 
          }),
          OPERATION_TIMEOUT,
          'search_code'
        );
        
        // Check for empty pages
        if (result.data.items.length === 0 && page && page > 1) {
          return formatToolResponse({ 
            message: "No more results",
            total_pages_checked: page,
            total_count: result.data.total_count
          });
        }
        
        // Simplify code search results
        const simplifiedItems = result.data.items.map(item => ({
          name: item.name,
          path: item.path,
          repository: {
            full_name: item.repository.full_name,
            private: item.repository.private
          },
          sha: item.sha,
          html_url: item.html_url,
          score: item.score
        }));
        
        const data = limitSearchResults({
          total_count: result.data.total_count,
          incomplete_results: result.data.incomplete_results,
          items: simplifiedItems
        }, result.data.items.length);
        
        return formatToolResponse(data, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, "search_code");
      }
    });

    // list_repositories - List repositories for authenticated user
    this.server.tool("list_repositories", "List repositories for authenticated user", {
      visibility: z.enum(["all", "public", "private"]).optional().describe("Repository visibility"),
      affiliation: z.enum(["owner", "collaborator", "organization_member"]).optional().describe("Repository affiliation"),
      type: z.enum(["all", "owner", "public", "private", "member"]).optional().describe("Repository type"),
      sort: z.enum(["created", "updated", "pushed", "full_name"]).optional().describe("Sort field"),
      direction: z.enum(["asc", "desc"]).optional().describe("Sort direction"),
      page: z.number().optional().describe("Page number"),
      perPage: perPageSchema.describe("Results per page (max 100)")
    }, async ({ visibility, affiliation, type, sort, direction, page, perPage }) => {
      // Validate pagination early
      const pageValidation = validatePagination(page);
      if (!pageValidation.isValid) {
        return formatToolResponse({ error: pageValidation.error });
      }

      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.repos.listForAuthenticatedUser({ 
            visibility, 
            affiliation, 
            type, 
            sort, 
            direction, 
            page, 
            per_page: Math.min(perPage || 30, 100) 
          }),
          OPERATION_TIMEOUT,
          'list_repositories'
        );
        
        // Simplify repository data
        const simplifiedRepos = result.data.map(simplifyRepoData);
        
        return formatToolResponse({
          repositories: simplifiedRepos,
          count: simplifiedRepos.length
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, "list_repositories");
      }
    });

    // list_repositories_by_org - List repositories for an organization
    this.server.tool("list_repositories_by_org", "List repositories for an organization", {
      org: githubUsernameSchema.describe("Organization name"),
      type: z.enum(["all", "public", "private", "forks", "sources", "member"]).optional().describe("Repository type filter"),
      sort: z.enum(["created", "updated", "pushed", "full_name"]).optional().describe("Sort field"),
      direction: z.enum(["asc", "desc"]).optional().describe("Sort direction"),
      page: z.number().optional().describe("Page number"),
      perPage: perPageSchema.describe("Results per page (max 100)")
    }, async ({ org, type, sort, direction, page, perPage }) => {
      // Validate pagination early
      const pageValidation = validatePagination(page);
      if (!pageValidation.isValid) {
        return formatToolResponse({ error: pageValidation.error });
      }

      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.repos.listForOrg({ 
            org, 
            type, 
            sort, 
            direction, 
            page, 
            per_page: Math.min(perPage || 30, 100) 
          }),
          OPERATION_TIMEOUT,
          `list_repositories_by_org ${org}`
        );
        
        // Simplify repository data
        const simplifiedRepos = result.data.map(simplifyRepoData);
        
        return formatToolResponse({
          organization: org,
          repositories: simplifiedRepos,
          count: simplifiedRepos.length
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `list_repositories_by_org ${org}`);
      }
    });

    // ==========================================
    // CODE SECURITY TOOLSET
    // ==========================================

    // get_code_scanning_alert - Get a code scanning alert
    this.server.tool("get_code_scanning_alert", "Get a code scanning alert", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      alertNumber: z.number().describe("Alert number")
    }, async ({ owner, repo, alertNumber }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.codeScanning.getAlert({ 
            owner, repo, alert_number: alertNumber 
          }),
          OPERATION_TIMEOUT,
          `get_code_scanning_alert ${owner}/${repo}#${alertNumber}`
        );
        
        return formatToolResponse({
          alert: sanitizeResponse(result.data)
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `get_code_scanning_alert ${owner}/${repo}#${alertNumber}`);
      }
    });

    // list_code_scanning_alerts - List code scanning alerts for a repository
    this.server.tool("list_code_scanning_alerts", "List code scanning alerts for a repository", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      ref: z.string().optional().describe("Git reference"),
      state: z.enum(["open", "dismissed", "fixed"]).optional().describe("Alert state"),
      severity: z.enum(["critical", "high", "medium", "low", "warning", "note", "error"]).optional().describe("Alert severity"),
      toolName: z.string().optional().describe("The name of the tool used for code scanning"),
      page: z.number().optional().describe("Page number"),
      perPage: perPageSchema.describe("Results per page (max 100)")
    }, async ({ owner, repo, ref, state, severity, toolName, page, perPage }) => {
      // Validate pagination early
      const pageValidation = validatePagination(page);
      if (!pageValidation.isValid) {
        return formatToolResponse({ error: pageValidation.error });
      }

      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.codeScanning.listAlertsForRepo({ 
            owner, 
            repo, 
            ref, 
            state, 
            severity, 
            tool_name: toolName,
            page,
            per_page: Math.min(perPage || 30, 100)
          }),
          OPERATION_TIMEOUT,
          `list_code_scanning_alerts ${owner}/${repo}`
        );
        
        // Simplify alert data
        const alerts = result.data.map(alert => ({
          number: alert.number,
          state: alert.state,
          rule: {
            id: alert.rule.id,
            severity: alert.rule.severity,
            description: alert.rule.description
          },
          tool: alert.tool,
          created_at: alert.created_at,
          html_url: alert.html_url
        }));
        
        return formatToolResponse({
          alerts,
          count: alerts.length
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `list_code_scanning_alerts ${owner}/${repo}`);
      }
    });

    // get_secret_scanning_alert - Get a secret scanning alert
    this.server.tool("get_secret_scanning_alert", "Get a secret scanning alert", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      alertNumber: z.number().describe("Alert number")
    }, async ({ owner, repo, alertNumber }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.secretScanning.getAlert({ 
            owner, repo, alert_number: alertNumber 
          }),
          OPERATION_TIMEOUT,
          `get_secret_scanning_alert ${owner}/${repo}#${alertNumber}`
        );
        
        return formatToolResponse({
          alert: sanitizeResponse(result.data)
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `get_secret_scanning_alert ${owner}/${repo}#${alertNumber}`);
      }
    });

    // list_secret_scanning_alerts - List secret scanning alerts for a repository
    this.server.tool("list_secret_scanning_alerts", "List secret scanning alerts for a repository", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      state: z.enum(["open", "resolved"]).optional().describe("Alert state"),
      secretType: z.string().optional().describe("The secret types to be filtered for in a comma-separated list"),
      resolution: z.enum(["false_positive", "wont_fix", "revoked", "used_in_tests"]).optional().describe("The resolution status"),
      page: z.number().optional().describe("Page number"),
      perPage: perPageSchema.describe("Results per page (max 100)")
    }, async ({ owner, repo, state, secretType, resolution, page, perPage }) => {
      // Validate pagination early
      const pageValidation = validatePagination(page);
      if (!pageValidation.isValid) {
        return formatToolResponse({ error: pageValidation.error });
      }

      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.secretScanning.listAlertsForRepo({ 
            owner, 
            repo, 
            state, 
            secret_type: secretType, 
            resolution,
            page,
            per_page: Math.min(perPage || 30, 100)
          }),
          OPERATION_TIMEOUT,
          `list_secret_scanning_alerts ${owner}/${repo}`
        );
        
        // Sanitize and simplify alert data
        const alerts = result.data.map(alert => ({
          number: alert.number,
          state: alert.state,
          secret_type: alert.secret_type,
          secret_type_display_name: alert.secret_type_display_name,
          resolution: alert.resolution,
          resolved_at: alert.resolved_at,
          created_at: alert.created_at,
          html_url: alert.html_url
        }));
        
        return formatToolResponse({
          alerts,
          count: alerts.length
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `list_secret_scanning_alerts ${owner}/${repo}`);
      }
    });

    // ==========================================
    // DEPENDABOT SECURITY TOOLSET
    // ==========================================

    // list_dependabot_alerts - List Dependabot alerts for a repository
    this.server.tool("list_dependabot_alerts", "List Dependabot security alerts for a repository", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      state: z.enum(["auto_dismissed", "dismissed", "fixed", "open"]).optional().describe("Alert state"),
      severity: z.enum(["low", "medium", "high", "critical"]).optional().describe("Alert severity"),
      ecosystem: z.string().optional().describe("Package ecosystem (e.g., npm, pip, maven)"),
      package: z.string().optional().describe("Package name"),
      scope: z.enum(["development", "runtime"]).optional().describe("Dependency scope"),
      sort: z.enum(["created", "updated"]).optional().describe("Sort field"),
      direction: z.enum(["asc", "desc"]).optional().describe("Sort direction"),
      page: z.number().optional().describe("Page number"),
      perPage: perPageSchema.describe("Results per page (max 100)")
    }, async ({ owner, repo, state, severity, ecosystem, package: pkg, scope, sort, direction, page, perPage }) => {
      // Validate pagination early
      const pageValidation = validatePagination(page);
      if (!pageValidation.isValid) {
        return formatToolResponse({ error: pageValidation.error });
      }

      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.dependabot.listAlertsForRepo({ 
            owner, 
            repo, 
            state, 
            severity, 
            ecosystem, 
            package: pkg,
            scope,
            sort,
            direction,
            page,
            per_page: Math.min(perPage || 30, 100)
          }),
          OPERATION_TIMEOUT,
          `list_dependabot_alerts ${owner}/${repo}`
        );
        
        // Simplify alert data
        const alerts = result.data.map(alert => ({
          number: alert.number,
          state: alert.state,
          security_advisory: {
            ghsa_id: alert.security_advisory.ghsa_id,
            summary: alert.security_advisory.summary,
            severity: alert.security_advisory.severity,
            description: alert.security_advisory.description.substring(0, 200) + '...'
          },
          security_vulnerability: {
            package: alert.security_vulnerability.package,
            vulnerable_version_range: alert.security_vulnerability.vulnerable_version_range,
            first_patched_version: alert.security_vulnerability.first_patched_version
          },
          dependency: {
            package: alert.dependency.package,
            manifest_path: alert.dependency.manifest_path,
            scope: alert.dependency.scope
          },
          created_at: alert.created_at,
          updated_at: alert.updated_at,
          fixed_at: alert.fixed_at,
          html_url: alert.html_url
        }));
        
        return formatToolResponse({
          alerts,
          count: alerts.length,
          summary: {
            critical: alerts.filter(a => a.security_advisory.severity === 'critical').length,
            high: alerts.filter(a => a.security_advisory.severity === 'high').length,
            medium: alerts.filter(a => a.security_advisory.severity === 'medium').length,
            low: alerts.filter(a => a.security_advisory.severity === 'low').length
          }
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `list_dependabot_alerts ${owner}/${repo}`);
      }
    });

    // get_dependabot_alert - Get a specific Dependabot alert
    this.server.tool("get_dependabot_alert", "Get details of a specific Dependabot alert", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      alertNumber: z.number().describe("Alert number")
    }, async ({ owner, repo, alertNumber }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.dependabot.getAlert({ 
            owner, repo, alert_number: alertNumber 
          }),
          OPERATION_TIMEOUT,
          `get_dependabot_alert ${owner}/${repo}#${alertNumber}`
        );
        
        return formatToolResponse({
          alert: sanitizeResponse(result.data)
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `get_dependabot_alert ${owner}/${repo}#${alertNumber}`);
      }
    });

    // update_dependabot_alert - Update a Dependabot alert
    this.server.tool("update_dependabot_alert", "Update the state of a Dependabot alert", {
      owner: githubUsernameSchema.describe("Repository owner"),
      repo: githubRepoNameSchema.describe("Repository name"),
      alertNumber: z.number().describe("Alert number"),
      state: z.enum(["dismissed", "open"]).describe("New state for the alert"),
      dismissedReason: z.enum(["fix_started", "inaccurate", "no_bandwidth", "not_used", "tolerable_risk"]).optional().describe("Reason for dismissal (required when state is 'dismissed')"),
      dismissedComment: z.string().optional().describe("Optional comment about the dismissal")
    }, async ({ owner, repo, alertNumber, state, dismissedReason, dismissedComment }) => {
      // Validate that dismissedReason is provided when dismissing
      if (state === 'dismissed' && !dismissedReason) {
        return formatToolResponse({
          error: "Validation error",
          message: "dismissedReason is required when setting state to 'dismissed'"
        });
      }

      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          retryWithBackoff(
            () => octokit.rest.dependabot.updateAlert({ 
              owner, 
              repo, 
              alert_number: alertNumber,
              state,
              dismissed_reason: dismissedReason,
              dismissed_comment: dismissedComment
            }),
            3,
            `update_dependabot_alert ${owner}/${repo}#${alertNumber}`
          ),
          OPERATION_TIMEOUT,
          `update_dependabot_alert ${owner}/${repo}#${alertNumber}`
        );
        
        return formatToolResponse({
          updated: true,
          alert: sanitizeResponse(result.data)
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `update_dependabot_alert ${owner}/${repo}#${alertNumber}`);
      }
    });

    // ==========================================
    // NOTIFICATIONS TOOLSET
    // ==========================================

    // list_notifications - List notifications for a GitHub user
    this.server.tool("list_notifications", "List notifications for a GitHub user", {
      all: z.boolean().optional().describe("Show all notifications, including read"),
      participating: z.boolean().optional().describe("Show only notifications in which the user is directly participating"),
      since: z.string().optional().describe("Only show notifications updated after the given time (ISO 8601 format)"),
      before: z.string().optional().describe("Only show notifications updated before the given time (ISO 8601 format)"),
      owner: githubUsernameSchema.optional().describe("Optional repository owner"),
      repo: githubRepoNameSchema.optional().describe("Optional repository name"),
      page: z.number().optional().describe("Page number"),
      perPage: perPageSchema.describe("Results per page (max 100)")
    }, async ({ all, participating, since, before, owner, repo, page, perPage }) => {
      // Validate pagination early
      const pageValidation = validatePagination(page);
      if (!pageValidation.isValid) {
        return formatToolResponse({ error: pageValidation.error });
      }

      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        if (owner && repo) {
          const result = await withTimeout(
            octokit.rest.activity.listRepoNotificationsForAuthenticatedUser({ 
              owner, 
              repo, 
              all, 
              participating, 
              since: parseDate(since), 
              before: parseDate(before), 
              page, 
              per_page: Math.min(perPage || 30, 100) 
            }),
            OPERATION_TIMEOUT,
            `list_notifications for ${owner}/${repo}`
          );
          
          return formatToolResponse({
            notifications: sanitizeResponse(result.data),
            count: result.data.length,
            repository: `${owner}/${repo}`
          }, rateCheck);
        } else {
          const result = await withTimeout(
            octokit.rest.activity.listNotificationsForAuthenticatedUser({ 
              all, 
              participating, 
              since: parseDate(since), 
              before: parseDate(before), 
              page, 
              per_page: Math.min(perPage || 30, 100) 
            }),
            OPERATION_TIMEOUT,
            'list_notifications'
          );
          
          return formatToolResponse({
            notifications: sanitizeResponse(result.data),
            count: result.data.length
          }, rateCheck);
        }
      } catch (error) {
        return formatErrorResponse(error, "list_notifications");
      }
    });

    // get_notification_details - Get detailed information for a specific GitHub notification
    this.server.tool("get_notification_details", "Get detailed information for a specific GitHub notification", {
      notificationId: z.string().describe("The ID of the notification")
    }, async ({ notificationId }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          octokit.rest.activity.getThread({ thread_id: parseInt(notificationId) }),
          OPERATION_TIMEOUT,
          `get_notification_details ${notificationId}`
        );
        
        return formatToolResponse({
          notification: sanitizeResponse(result.data)
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `get_notification_details ${notificationId}`);
      }
    });

    // dismiss_notification - Dismiss a notification by marking it as read or done
    this.server.tool("dismiss_notification", "Dismiss a notification by marking it as read or done", {
      threadId: z.string().describe("The ID of the notification thread")
    }, async ({ threadId }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          retryWithBackoff(
            () => octokit.rest.activity.markThreadAsRead({ thread_id: parseInt(threadId) }),
            3,
            `dismiss_notification ${threadId}`
          ),
          OPERATION_TIMEOUT,
          `dismiss_notification ${threadId}`
        );
        
        return formatToolResponse({
          marked_as_read: true,
          thread_id: threadId,
          status: result.status
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `dismiss_notification ${threadId}`);
      }
    });

    // mark_all_notifications_read - Mark all notifications as read
    this.server.tool("mark_all_notifications_read", "Mark all notifications as read", {
      lastReadAt: z.string().optional().describe("Describes the last point that notifications were checked (RFC3339/ISO8601 string, default: now)"),
      owner: githubUsernameSchema.optional().describe("Optional repository owner"),
      repo: githubRepoNameSchema.optional().describe("Optional repository name")
    }, async ({ lastReadAt, owner, repo }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        if (owner && repo) {
          const result = await withTimeout(
            retryWithBackoff(
              () => octokit.rest.activity.markRepoNotificationsAsRead({ 
                owner, repo, last_read_at: parseDate(lastReadAt) || new Date().toISOString()
              }),
              3,
              `mark_all_notifications_read for ${owner}/${repo}`
            ),
            OPERATION_TIMEOUT,
            `mark_all_notifications_read for ${owner}/${repo}`
          );
          
          return formatToolResponse({
            marked_all_as_read: true,
            repository: `${owner}/${repo}`,
            status: result.status
          }, rateCheck);
        } else {
          const result = await withTimeout(
            retryWithBackoff(
              () => octokit.rest.activity.markNotificationsAsRead({ 
                last_read_at: parseDate(lastReadAt) || new Date().toISOString()
              }),
              3,
              'mark_all_notifications_read'
            ),
            OPERATION_TIMEOUT,
            'mark_all_notifications_read'
          );
          
          return formatToolResponse({
            marked_all_as_read: true,
            status: result.status
          }, rateCheck);
        }
      } catch (error) {
        return formatErrorResponse(error, "mark_all_notifications_read");
      }
    });

    // manage_notification_subscription - Manage a notification subscription (ignore, watch, or delete) for a notification thread
    this.server.tool("manage_notification_subscription", "Manage a notification subscription for a notification thread", {
      notificationId: z.string().describe("The ID of the notification thread"),
      subscribed: z.boolean().optional().describe("Whether to subscribe to or unsubscribe from the thread"),
      ignored: z.boolean().optional().describe("Whether to ignore or un-ignore the thread")
    }, async ({ notificationId, subscribed, ignored }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          retryWithBackoff(
            () => octokit.rest.activity.setThreadSubscription({ 
              thread_id: parseInt(notificationId), subscribed, ignored 
            }),
            3,
            `manage_notification_subscription ${notificationId}`
          ),
          OPERATION_TIMEOUT,
          `manage_notification_subscription ${notificationId}`
        );
        
        return formatToolResponse({
          updated: true,
          subscription: sanitizeResponse(result.data)
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `manage_notification_subscription ${notificationId}`);
      }
    });

    // manage_repository_notification_subscription - Manage a repository notification subscription
    this.server.tool("manage_repository_notification_subscription", "Manage a repository notification subscription", {
      owner: githubUsernameSchema.describe("The account owner of the repository"),
      repo: githubRepoNameSchema.describe("The name of the repository"),
      subscribed: z.boolean().optional().describe("Whether to subscribe to or unsubscribe from the repository"),
      ignored: z.boolean().optional().describe("Whether to ignore or un-ignore repository notifications")
    }, async ({ owner, repo, subscribed, ignored }) => {
      try {
        const octokit = new Octokit({ auth: this.props.accessToken });
        
        const rateCheck = await checkRateLimit(octokit);
        if (!rateCheck.canContinue) {
          return formatToolResponse({ error: "Rate limit exceeded", ...rateCheck });
        }
        
        const result = await withTimeout(
          retryWithBackoff(
            () => octokit.rest.activity.setRepoSubscription({ 
              owner, repo, subscribed, ignored 
            }),
            3,
            `manage_repository_notification_subscription ${owner}/${repo}`
          ),
          OPERATION_TIMEOUT,
          `manage_repository_notification_subscription ${owner}/${repo}`
        );
        
        return formatToolResponse({
          updated: true,
          repository: `${owner}/${repo}`,
          subscription: sanitizeResponse(result.data)
        }, rateCheck);
      } catch (error) {
        return formatErrorResponse(error, `manage_repository_notification_subscription ${owner}/${repo}`);
      }
    });
  }
}

// Feature flags
const AUTO_REGISTER_CLIENTS = true;
const ALLOW_CUSTOM_GITHUB_APPS = true;
const DEBUG_REQUESTS = true; // Activar logs de debugging

// Auto-registro dinámico de clientes OAuth
async function autoRegisterClient(request: Request, env: Env): Promise<void> {
  const url = new URL(request.url);
  
  // Solo procesar requests relevantes
  if (!url.pathname.match(/\/(authorize|token)/)) {
    return;
  }
  
  if (DEBUG_REQUESTS) {
    console.log('[autoRegister] Processing request for:', url.pathname);
  }
  
  // Extraer client_id de diferentes fuentes
  let clientId: string | null = null;
  
  if (request.method === 'GET') {
    clientId = url.searchParams.get('client_id');
  } else if (request.method === 'POST') {
    try {
      const body = await request.clone().text();
      const params = new URLSearchParams(body);
      clientId = params.get('client_id');
    } catch {
      // Ignorar errores de parsing
    }
  }
  
  if (!clientId) return;
  
  // Verificar si ya existe
  const clientKey = `oauth_client:${clientId}`;
  const existing = await env.OAUTH_KV.get(clientKey);
  
  if (!existing) {
    // Crear cliente dinámicamente
    const newClient = {
      client_id: clientId,
      client_secret: "", // Cliente público por defecto
      redirect_uris: [
        "https://claude.ai/api/mcp/auth_callback",
        "http://localhost:3000/callback", // Para desarrollo
        `${url.origin}/callback` // Callback del propio servidor
      ],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      scope: "claudeai openai mcp", // Scopes genéricos
      client_name: `Auto-registered client ${clientId}`,
      token_endpoint_auth_method: "none", // Cliente público
      created_at: new Date().toISOString(),
      auto_registered: true
    };
    
    await env.OAUTH_KV.put(clientKey, JSON.stringify(newClient));
    console.log(`Auto-registered OAuth client: ${clientId}`);
    
    // Actualizar índice si existe
    const indexKey = 'oauth_clients:index';
    const index = await env.OAUTH_KV.get(indexKey);
    const clients = index ? JSON.parse(index) : [];
    if (!clients.includes(clientId)) {
      clients.push(clientId);
      await env.OAUTH_KV.put(indexKey, JSON.stringify(clients));
    }
  }
}

// Crear el provider original
const provider = new OAuthProvider({
  apiRoute: "/sse",
  apiHandler: MyMCP.mount("/sse") as any,
  defaultHandler: GitHubHandler as any,
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/token",
  clientRegistrationEndpoint: "/register",
});

// ALTERNATIVA: Si el 404 persiste, prueba este export más simple:
// export default new OAuthProvider({
//   apiRoute: "/sse",
//   apiHandler: MyMCP.mount("/sse") as any,
//   defaultHandler: GitHubHandler as any,
//   authorizeEndpoint: "/authorize",
//   tokenEndpoint: "/token",
//   clientRegistrationEndpoint: "/register",
// });

// Exportar con wrapper para auto-registro y debugging
export default {
  fetch: async (request: Request, env: Env, ctx: ExecutionContext): Promise<Response> => {
    // Log para debugging
    if (DEBUG_REQUESTS) {
      const url = new URL(request.url);
      console.log(`[MCP] ${request.method} ${url.pathname}${url.search}`);
    }
    
    // Auto-registrar cliente si está habilitado
    if (AUTO_REGISTER_CLIENTS) {
      await autoRegisterClient(request, env);
    }
    
    // Delegar al provider original
    try {
      const response = await provider.fetch(request, env, ctx);
      if (DEBUG_REQUESTS) {
        console.log(`[MCP] Response status: ${response.status}`);
      }
      return response;
    } catch (error) {
      console.error('[MCP] Error handling request:', error);
      throw error;
    }
  }
};