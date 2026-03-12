// ── Tools de Escritura v5 (Titanium) ───────────────────────────────────────────
// Interfaz RCP para mutación controlada de secretos en GCP.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SecretManagerService } from "../services/SecretManagerService.js";
import { CreateSecretSchema, AddVersionSchema, DisableVersionSchema } from "../schemas/secrets.js";

const ok = (data: unknown) => ({
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
});

const err = (msg: string) => ({
    isError: true as const,
    content: [{ type: "text" as const, text: `MUTATION_DENIED: ${msg}` }],
});

export function registerWriteTools(
    server: McpServer,
    svc: SecretManagerService,
    clientId: () => string,
): void {

    server.registerTool("vault_create_secret", {
        description: "Crea un secreto con label de boveda mcp-accessible=true para auditoría.",
        inputSchema: CreateSecretSchema,
    }, async (p) => {
        try { return ok(await svc.createSecret(p.secretId, p.labels ?? {}, clientId())); }
        catch (e) { return err(e instanceof Error ? e.message : "Creation Refused"); }
    });

    server.registerTool("vault_add_version", {
        description: "Rotar secreto (nueva versión). Notifica vía Pub/Sub a receptores.\n⚠️ Alta Sensibilidad.",
        inputSchema: AddVersionSchema,
    }, async (p) => {
        try { return ok({ secretId: p.secretId, newVersion: await svc.addSecretVersion(p.secretId, p.value, clientId()) }); }
        catch (e) { return err(e instanceof Error ? e.message : "Rotation Denied"); }
    });

    server.registerTool("vault_disable_version", {
        description: "Invalida una versión específica del contenedor. Acción destructiva en acceso.",
        inputSchema: DisableVersionSchema,
    }, async (p) => {
        try { return ok(await svc.disableVersion(p.secretId, p.version, clientId())); }
        catch (e) { return err(e instanceof Error ? e.message : "Invalidation Failed"); }
    });
}
