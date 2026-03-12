// ── Tools de Contexto v5 (Titanium) ──────────────────────────────────────────
// Sinterización de entornos persistentes para cargas de trabajo seguras.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SecretManagerService } from "../services/SecretManagerService.js";
import { SynthesizeEnvSchema } from "../schemas/secrets.js";

const ok = (data: unknown) => ({
  content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
});

const err = (msg: string) => ({
  isError: true as const,
  content: [{ type: "text" as const, text: `CONTEXT_VIOLATION: ${msg}` }],
});

export function registerContextTools(
  server: McpServer,
  svc: SecretManagerService,
  clientId: () => string,
): void {

  server.registerTool("vault_synthesize_env", {
    description: "Genera una estructura de entorno .env resolviendo múltiples secretos.",
    inputSchema: SynthesizeEnvSchema,
  }, async (p) => {
    try { return ok(await svc.synthesizeEnv(p.secretIds, clientId(), p.reason)); }
    catch (e) { return err(e instanceof Error ? e.message : "Synthesis Denied"); }
  });
}
