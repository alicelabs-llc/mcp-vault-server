// ── MCP Vault Entrypoint v5 (Titanium) ──────────────────────────────────────
// Transporte HTTP/SSE para comunicación blindada con el SDK MCP.

import express from "express";
import { createServer } from "http";
import cors from "cors";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import {
    SERVER_NAME,
    SERVER_VERSION,
    DEFAULT_PORT,
    MAX_JSON_BODY_SIZE,
    SHUTDOWN_TIMEOUT_MS,
    REQUEST_ID_REGEX
} from "./constants.js";
import { loadConfig } from "./config.js";
import { createServices, createMcpServer, requestContext } from "./server.js";
import { authMiddleware } from "./middleware/auth.js";
import { rateLimitMiddleware } from "./middleware/rateLimiter.js";
import { randomUUID } from "crypto";
import type { IncomingMessage, ServerResponse } from "http";

const config = loadConfig();
const app = express();
const httpServer = createServer(app);

// ── Inyección de Servicios ────────────────────────────────────────────────────
const { audit, svc, pubsub } = createServices(config);
const mcpServer = createMcpServer({ audit, svc, pubsub });

// ── Blindaje de Protocolo (Security Headers) ──────────────────────────────────
app.disable("x-powered-by");

app.use((req, res, next) => {
    let requestId = req.headers["x-request-id"];
    if (typeof requestId !== "string" || !REQUEST_ID_REGEX.test(requestId)) {
        requestId = randomUUID();
    }
    res.setHeader("X-Request-Id", requestId);
    (req as any).requestId = requestId;

    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
    res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=(), usb=()");
    res.setHeader("Server", `${SERVER_NAME}/${SERVER_VERSION}`);

    next();
});

// ── Sistema de CORS ────────────────────────────────────────────────────────────
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || config.allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            audit.log({ action: "security_breach", secretId: null, clientId: "sys", success: false, reason: `CORS_VIOLATION: ${origin}` });
            callback(new Error("Violation of same-origin or allowed-origins policy"));
        }
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Request-Id"],
    maxAge: 86400,
}));

app.use(express.json({ limit: MAX_JSON_BODY_SIZE }));

// ── Puntos de Control Anónimos ────────────────────────────────────────────────
app.get("/health", (req, res) => {
    const stats = svc.circuitBreakerStats;
    res.status(stats.state !== "OPEN" ? 200 : 503).json({
        status: stats.state !== "OPEN" ? "OK" : "DEGRADED",
        version: SERVER_VERSION,
        timestamp: new Date().toISOString()
    });
});

// ── Transporte MCP (SSE) ──────────────────────────────────────────────────────
let transport: SSEServerTransport | null = null;

app.get("/sse",
    rateLimitMiddleware(audit),
    authMiddleware(config),
    async (req, res) => {
        const clientId = (req as any).clientId;

        transport = new SSEServerTransport("/messages", res as unknown as ServerResponse);
        await mcpServer.connect(transport);

        audit.log({ action: "notify_rotation", secretId: null, clientId, success: true, reason: "SSE_CONNECTION_ESTABLISHED" });
        process.stderr.write(`🔌 SSE: Connected ${clientId} [${(req as any).requestId}]\n`);
    }
);

app.post("/messages",
    rateLimitMiddleware(audit),
    authMiddleware(config),
    async (req, res) => {
        if (!transport) {
            res.status(400).json({ error: "Missing active SSE connection" });
            return;
        }

        const clientId = (req as any).clientId;

        await requestContext.run({ clientId }, async () => {
            // Cast a any para asegurar compatibilidad con los tipos extendidos de Express
            await transport!.handlePostMessage(req as unknown as IncomingMessage, res as unknown as ServerResponse);
        });
    }
);

// ── Manejo Global de Errores ──────────────────────────────────────────────────
app.use((req, res) => {
    res.status(404).json({ error: "Operation not found" });
});

app.use((err: any, req: any, res: any, next: any) => {
    const reqId = req.requestId;
    audit.logError("security_breach", null, req.clientId || "sys", "GLOBAL_SYSTEM_ERROR", err.stack || err.message);

    if (res.headersSent) return next(err);

    res.status(err.status || 500).json({
        error: "Internal Security Error",
        message: "A security or protocol violation occurred.",
        requestId: reqId
    });
});

// ── Inicio y Shutdown ─────────────────────────────────────────────────────────
const PORT = process.env.PORT || config.port || DEFAULT_PORT;
httpServer.listen(PORT, () => {
    process.stderr.write(`🚀 ${SERVER_NAME} v${SERVER_VERSION} online at port ${PORT}\n`);
});

function gracefulShutdown(signal: string) {
    process.stderr.write(`\n🛑 Signal [${signal}]: Shutting down services\n`);
    httpServer.close(() => {
        svc.destroy();
        process.exit(0);
    });

    setTimeout(() => {
        process.stderr.write("⚠️ Force shutdown timeout exceeded\n");
        process.exit(1);
    }, SHUTDOWN_TIMEOUT_MS);
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("unhandledRejection", (reason: any) => {
    const msg = reason instanceof Error ? reason.message : String(reason);
    audit.logError("security_breach", null, "sys", "UNHANDLED_REJECTION", msg);
    process.stderr.write(`🚨 UNHANDLED_REJECTION: ${msg}\n`);
});
