# Fix: decodeBase64 UTF-8 support

## Archivo a modificar
`github-mcp-server/src/index.ts` — función `decodeBase64` (línea ~139)

## Bug
`atob()` solo maneja ASCII. Archivos con caracteres Unicode (fórmulas matemáticas,
flechas →, letras griegas λ, Φ, operadores ⊊, etc.) producen `Error occurred during
tool execution` en `get_file_contents`.

Archivos afectados: cualquier Markdown con contenido formal/matemático (ej: DERIVACION_UNIFICADA_v2.0.md).
Archivos que funcionan: ASCII puro (ej: TSCC_T22_v3.thy, 13k bytes).

## Cambio exacto

### ANTES (reemplazar estas líneas):
```typescript
const decodeBase64 = (base64: string): string => {
  try {
    return atob(base64.replace(/\n/g, ''));
  } catch {
    return base64; // Return as-is if decode fails
  }
};
```

### DESPUÉS (reemplazar con):
```typescript
const decodeBase64 = (base64: string): string => {
  try {
    // FIX: atob() is ASCII-only. Files with Unicode content (math formulas, arrows,
    // Greek letters, etc.) require UTF-8 decoding via Uint8Array + TextDecoder.
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
```

## Aplicar y desplegar
```bash
git checkout fix/decode-base64-utf8-v2
# Aplicar el cambio de arriba en github-mcp-server/src/index.ts
cd github-mcp-server
npm run deploy  # o: wrangler deploy
```

## Verificación
Después del deploy, `get_file_contents` para archivos con Unicode debe funcionar:
```
owner: zaste, repo: CI-PAT-0, path: CCI_v1.0/00_CADENA/META/DERIVACION_UNIFICADA_v2.0.md
```
