// ── McpServer Factory v5 (Titanium) ──────────────────────────────────────────
// Orquestación central de servicios y registro de utilidades del protocolo.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { AsyncLocalStorage } from "async_hooks";
import { SecretManagerService } from "./services/SecretManagerService.js";
import { AuditService } from "./services/AuditService.js";
import { PubSubService } from "./services/PubSubService.js";
import { registerReadTools } from "./tools/readTools.js";
import { registerWriteTools } from "./tools/writeTools.js";
import { registerContextTools } from "./tools/contextTools.js";
import { SERVER_NAME, SERVER_VERSION } from "./constants.js";
import type { ServerConfig } from "./types.js";

/** 
 * Contexto asíncrono seguro para propagar el `clientId` desde el middleware
 * de autenticación hasta el servicio de auditoría, sin polucionar firmas de funciones.
 */
export const requestContext = new AsyncLocalStorage<{ clientId: string }>();

export interface McpVaultServices {
    readonly audit: AuditService;
    readonly pubsub: PubSubService;
    readonly svc: SecretManagerService;
}

/**
 * Crea las instancias de servicio blindadas. Único punto de entrada
 * para la creación del grafo de dependencias del servidor.
 */
export function createServices(config: ServerConfig): McpVaultServices {
    const audit = new AuditService(config.projectId);
    const pubsub = new PubSubService(config.pubSubTopic, config.projectId, audit);
    const svc = new SecretManagerService(config.projectId, audit, pubsub);

    return { audit, pubsub, svc };
}

/**
 * Crea y registra el servidor MCP Titanium.
 * Inyecta herramientas de lectura, escritura y contexto en el servidor.
 */
export function createMcpServer(services: McpVaultServices): McpServer {
    // Constructor Titanium minimalista para compatibilidad total con el SDK
    const server = new McpServer({
        name: SERVER_NAME,
        version: SERVER_VERSION
    });

    const clientId = () => requestContext.getStore()?.clientId ?? "anonymous";

    // Registro de herramientas modularizado y blindado
    registerReadTools(server, services.svc, clientId);
    registerWriteTools(server, services.svc, clientId);
    registerContextTools(server, services.svc, clientId);

    return server;
}
