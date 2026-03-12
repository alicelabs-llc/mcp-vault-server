// ── Config v5.2 (Titanium) ───────────────────────────────────────────────────
// Carga y validación atómica con soporte extremo de tipos para compilador TS.

import { z } from "zod";
import { DEFAULT_PORT } from "./constants.js";
import type { ServerConfig } from "./types.js";

const ConfigSchema = z.object({
    GCP_PROJECT_ID: z.string().min(1).trim(),
    PORT: z.preprocess((val) => {
        if (typeof val === "string") return parseInt(val, 10);
        return val;
    }, z.number().int().min(1).max(65535).default(DEFAULT_PORT)),
    TRANSPORT: z.enum(["http", "stdio"]).default("http"),
    MCP_AUTH_TOKENS: z.string().min(1).transform((val) => {
        const tokens = val.split(",").map(t => t.trim()).filter(Boolean);
        if (tokens.length === 0) throw new Error("MCP_AUTH_TOKENS no puede estar vacío");
        return new Set(tokens);
    }),
    PUBSUB_ROTATION_TOPIC: z.string().optional().nullable().default(null),
    ALLOWED_ORIGINS: z.string().optional().default("").transform((val) =>
        val.split(",").map(o => o.trim()).filter(Boolean)
    ),
});

export function loadConfig(): ServerConfig {
    try {
        const parsed = ConfigSchema.parse(process.env);

        const config: ServerConfig = {
            projectId: parsed.GCP_PROJECT_ID,
            port: parsed.PORT,
            transport: parsed.TRANSPORT,
            authTokens: parsed.MCP_AUTH_TOKENS as ReadonlySet<string>,
            allowedOrigins: parsed.ALLOWED_ORIGINS,
            pubSubTopic: parsed.PUBSUB_ROTATION_TOPIC,
        };

        process.stderr.write(`✅ Config Titanium Loaded: project=${config.projectId}, port=${config.port}\n`);
        return config;
    } catch (e: any) {
        process.stderr.write("❌ Critical Configuration Error:\n");
        if (e && typeof e === 'object' && "errors" in e && Array.isArray(e.errors)) {
            e.errors.forEach((err: any) => {
                process.stderr.write(`   - ${err.path.join(".")}: ${err.message}\n`);
            });
        } else {
            process.stderr.write(`   - Root: ${String(e)}\n`);
        }
        process.exit(1);
    }
}
