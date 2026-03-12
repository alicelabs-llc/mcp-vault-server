// ── Rate Limiter v5 (Titanium) ───────────────────────────────────────────────
// Protección contra DoS y Brute-force con awareness de proxies confiables.

import type { Request, Response, NextFunction } from "express";
import {
    RATE_LIMIT_MAX,
    RATE_LIMIT_WINDOW_MS,
    RATE_LIMIT_STORE_MAX,
    RATE_LIMIT_PURGE_INTERVAL_MS
} from "../constants.js";
import type { RateLimitEntry } from "../types.js";
import { AuditService } from "../services/AuditService.js";

const store = new Map<string, RateLimitEntry>();

// Purga periódica para evitar crecimiento indefinido
setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of store) {
        if (now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
            store.delete(key);
        }
    }
}, RATE_LIMIT_PURGE_INTERVAL_MS).unref();

function evictIfNeeded(): void {
    if (store.size >= RATE_LIMIT_STORE_MAX) {
        // Eliminar el 10% más antiguo para mantener estabilidad de memoria
        const toRemove = Math.ceil(RATE_LIMIT_STORE_MAX * 0.1);
        const keys = store.keys();
        for (let i = 0; i < toRemove; i++) {
            const k = keys.next().value;
            if (k !== undefined) store.delete(k); else break;
        }
    }
}

/**
 * Middleware factory para inyectar servicios de auditoría.
 */
export function rateLimitMiddleware(audit?: AuditService) {
    return (req: Request, res: Response, next: NextFunction): void => {
        /**
         * Identificación de IP.
         * En GCP Cloud Run, la IP real viene en req.ip si trust proxy está activo.
         * Para una plataforma blindada, usamos req.ip como fuente principal.
         */
        const id = req.ip ?? req.socket.remoteAddress ?? "unknown";
        const now = Date.now();
        const entry = store.get(id);

        if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
            evictIfNeeded();
            store.set(id, { count: 1, windowStart: now });
            next();
            return;
        }

        if (entry.count >= RATE_LIMIT_MAX) {
            const waitMs = RATE_LIMIT_WINDOW_MS - (now - entry.windowStart);
            const retryAfter = Math.ceil(waitMs / 1000);

            res.set("Retry-After", String(retryAfter));

            if (audit) {
                audit.log({
                    action: "rate_limit_exceeded",
                    secretId: null,
                    clientId: id,
                    success: false,
                    reason: `THROTTLED: Limit of ${RATE_LIMIT_MAX} req/min exceeded`,
                    sourceIp: id
                });
            }

            res.status(429).json({
                error: "Too Many Requests",
                message: `Límite de ${RATE_LIMIT_MAX} peticiones por minuto excedido para la IP ${id}`,
                retryAfterSeconds: retryAfter,
            });
            return;
        }

        entry.count++;
        next();
    };
}
