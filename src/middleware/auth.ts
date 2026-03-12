// ── Auth Middleware v5 (Titanium) ─────────────────────────────────────────────
// Zero-information leakage: imposible distinguir 401 de 403 por timing o contenido.
import { createHash, timingSafeEqual, randomBytes } from "crypto";
import type { Request, Response, NextFunction } from "express";
import type { ServerConfig } from "../types.js";
import { AUTH_JITTER_MIN_MS, AUTH_JITTER_MAX_MS } from "../constants.js";

/**
 * Genera un fingerprint corto del token para logs de auditoría.
 * Usamos SHA-256 truncado a 8 hex chars — suficiente para correlación,
 * imposible de revertir al token original.
 */
export function tokenId(token: string): string {
    return createHash("sha256").update(token).digest("hex").slice(0, 8);
}

/**
 * Comparación timing-safe que es resistente a timing side-channels.
 * Ambos tokens se hashean antes de compararse, asegurando longitud constante
 * y que el atacante no pueda inferir prefijos correctos por timing.
 */
function safeCompare(token: string, secretToken: string): boolean {
    const tBuf = createHash("sha256").update(token).digest();
    const sBuf = createHash("sha256").update(secretToken).digest();
    return timingSafeEqual(tBuf, sBuf);
}

/**
 * Jitter criptográficamente seguro para todas las respuestas de error de auth.
 * Usa randomBytes (CSPRNG) en lugar de Math.random() para impedir predicción
 * del delay por un atacante con acceso a la semilla PRNG.
 */
function authJitter(): Promise<void> {
    const jitterRange = AUTH_JITTER_MAX_MS - AUTH_JITTER_MIN_MS;
    const randomDelay = AUTH_JITTER_MIN_MS + (randomBytes(2).readUInt16BE(0) % jitterRange);
    return new Promise(r => setTimeout(r, randomDelay));
}

/** Respuesta genérica de error de auth — siempre idéntica para 401 y 403 */
const AUTH_ERROR_RESPONSE = Object.freeze({
    error: "Unauthorized",
    message: "Invalid or missing credentials",
});

export function authMiddleware(config: ServerConfig) {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        const authHeader = req.headers["authorization"];

        // Si no hay header o no empieza con "Bearer ", error genérico
        if (!authHeader?.startsWith("Bearer ")) {
            await authJitter();
            res.status(401).json(AUTH_ERROR_RESPONSE);
            return;
        }

        // Extraer token — slice es O(1) y no se rompe con tokens que contengan espacios
        const token = authHeader.slice("Bearer ".length);

        if (!token || token.length === 0) {
            await authJitter();
            res.status(401).json(AUTH_ERROR_RESPONSE);
            return;
        }

        // Validar longitud máxima para prevenir DoS por tokens absurdamente largos
        if (token.length > 4096) {
            await authJitter();
            res.status(401).json(AUTH_ERROR_RESPONSE);
            return;
        }

        // Comparación timing-safe contra todos los tokens configurados
        let isValid = false;
        for (const t of config.authTokens) {
            if (safeCompare(token, t)) {
                isValid = true;
                break;
            }
        }

        if (!isValid) {
            await authJitter();
            // Respuesta idéntica a 401 — el atacante NO puede distinguir
            // "token ausente" de "token incorrecto"
            res.status(401).json(AUTH_ERROR_RESPONSE);
            return;
        }

        // Inyectar client fingerprint en el request
        (req as any).clientId = tokenId(token);
        next();
    };
}
