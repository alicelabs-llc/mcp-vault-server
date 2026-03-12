// ── Tools de Lectura v5 (Titanium) ─────────────────────────────────────────────
// Interfaz MCP para introspección y filtrado de la bóveda de secretos.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SecretManagerService } from "../services/SecretManagerService.js";
import {
    GetSecretSchema, GetMetadataSchema, ListSecretsSchema,
    ListVersionsSchema, PermissionCheckSchema,
} from "../schemas/secrets.js";
import { CHARACTER_LIMIT, SERVER_VERSION } from "../constants.js";

const trunc = (t: string) =>
    t.length <= CHARACTER_LIMIT ? t : t.slice(0, CHARACTER_LIMIT) + "\n\n[TRUNCATED BY SECURITY POLICY]";

const ok = (data: unknown) => ({
    content: [{ type: "text" as const, text: trunc(JSON.stringify(data, null, 2)) }],
});

const err = (msg: string) => ({
    isError: true as const,
    content: [{ type: "text" as const, text: `SECURITY_VIOLATION: ${msg}` }],
});

export function registerReadTools(
    server: McpServer,
    svc: SecretManagerService,
    clientId: () => string,
): void {

    server.registerTool("vault_check_permission", {
        description: "Verifica si un secreto tiene el label mcp-accessible=true para auditoría.",
        inputSchema: PermissionCheckSchema,
    }, async (p) => {
        try { return ok(await svc.checkPermission(p.secretId, clientId())); }
        catch (e) { return err(e instanceof Error ? e.message : "Internal Check Error"); }
    });

    server.registerTool("vault_get_secret", {
        description: `Obtiene el valor real de un secreto. Requiere un 'reason' descriptivo.\n⚠️ Alta Sensibilidad.`,
        inputSchema: GetSecretSchema,
    }, async (p) => {
        try {
            return ok({
                secretId: p.secretId,
                version: p.version,
                value: await svc.getSecretValue(p.secretId, p.version!, clientId(), p.reason),
            });
        }
        catch (e) { return err(e instanceof Error ? e.message : "Access Refused"); }
    });

    server.registerTool("vault_get_metadata", {
        description: "Obtiene información estructural del secreto SIN revelar su valor.",
        inputSchema: GetMetadataSchema,
    }, async (p) => {
        try { return ok(await svc.getSecretMetadata(p.secretId, clientId())); }
        catch (e) { return err(e instanceof Error ? e.message : "Metadata Fetch Failed"); }
    });

    server.registerTool("vault_list_secrets", {
        description: "Lista secretos habilitados para MCP en el inventario actual.",
        inputSchema: ListSecretsSchema,
    }, async (p) => {
        try { return ok(await svc.listSecrets(clientId(), p.pageSize, p.pageToken)); }
        catch (e) { return err(e instanceof Error ? e.message : "Inventory List Denied"); }
    });

    server.registerTool("vault_list_versions", {
        description: "Obtiene el historial de versiones activas de un secreto.",
        inputSchema: ListVersionsSchema,
    }, async (p) => {
        try { return ok(await svc.listVersions(p.secretId, clientId())); }
        catch (e) { return err(e instanceof Error ? e.message : "Version History Denied"); }
    });

    server.registerTool("vault_server_status", {
        description: "Diagnóstico operacional del servidor de bóveda.",
        inputSchema: {},
    }, async () => {
        return ok({
            version: SERVER_VERSION,
            status: "ready",
            circuitBreaker: svc.circuitBreakerStats.state,
            cacheStatus: "encrypted-in-memory",
            timestamp: new Date().toISOString(),
        });
    });
}
