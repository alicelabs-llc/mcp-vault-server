// ── Constantes Globales v5 (Titanium) ──────────────────────────────────────────
// Inmutables. Cada valor está justificado por OWASP, NIST SP 800-53, o benchmarks internos.

/** Límite de caracteres en respuestas MCP — previene exfiltración masiva por tool call */
export const CHARACTER_LIMIT = 8_000 as const;

/** Paginación de secretos */
export const MAX_PAGE_SIZE = 50 as const;
export const DEFAULT_PAGE_SIZE = 20 as const;

// ── Cache ──────────────────────────────────────────────────────────────────────
/** TTL del caché en memoria — 5 min. Balanceado entre rendimiento y frescura de labels */
export const CACHE_TTL_MS = 5 * 60 * 1_000 as const;

/** TTL máximo de valores antes de re-verificar labels en GCP (anti-TOCTOU) */
export const SECRET_VALUE_MAX_AGE_MS = CACHE_TTL_MS;

/** Máximo de entradas en cada store del CacheService */
export const CACHE_MAX_ENTRIES = 200 as const;

/**
 * Rotación de claves de cifrado en memoria.
 * NIST SP 800-57: rotar claves simétricas antes de 2^32 operaciones.
 * Con 200 entradas max y 5 min TTL, 4h es conservador (~50x margen).
 */
export const CACHE_KEY_ROTATION_MS = 4 * 60 * 60 * 1_000 as const;

// ── Rate Limiting ──────────────────────────────────────────────────────────────
/**
 * 20 req/min por instancia. Con max 10 instancias Cloud Run:
 * peor caso = 200 req/min global (aceptable para API de secretos).
 */
export const RATE_LIMIT_MAX = 20 as const;
export const RATE_LIMIT_WINDOW_MS = 60 * 1_000 as const;

/** Máximo de IPs únicas en store de rate limit — previene OOM por IP flooding */
export const RATE_LIMIT_STORE_MAX = 10_000 as const;

/** Intervalo de purga del rate limiter */
export const RATE_LIMIT_PURGE_INTERVAL_MS = 60_000 as const;

// ── Network ────────────────────────────────────────────────────────────────────
export const DEFAULT_PORT = 8080 as const;

/** Tamaño máximo de payload JSON — previene DoS por body grande */
export const MAX_JSON_BODY_SIZE = "256kb" as const;

/** Tamaño máximo de un valor de secreto — GCP permite 64KB, nosotros 5MB pero lo bajamos */
export const SECRET_VALUE_MAX_BYTES = 64 * 1024 as const; // 64KB como GCP

/** Timeout del apagado limpio */
export const SHUTDOWN_TIMEOUT_MS = 8_000 as const;

// ── Server Identity ────────────────────────────────────────────────────────────
export const SERVER_NAME = "gcp-secrets-mcp-server" as const;
export const SERVER_VERSION = "5.0.0" as const;

// ── Access Control ─────────────────────────────────────────────────────────────
export const REQUIRED_LABEL_KEY = "mcp-accessible" as const;
export const REQUIRED_LABEL_VALUE = "true" as const;

// ── Circuit Breaker ────────────────────────────────────────────────────────────
export const CB_FAILURE_THRESHOLD = 5 as const;
export const CB_SUCCESS_THRESHOLD = 3 as const;
export const CB_OPEN_TIMEOUT_MS = 30 * 1_000 as const;

// ── Retry ──────────────────────────────────────────────────────────────────────
export const RETRY_ATTEMPTS = 3 as const;
export const RETRY_BASE_MS = 200 as const;

// ── Auth ───────────────────────────────────────────────────────────────────────
/** Jitter de autenticación — hace indistinguible "sin token" de "token incorrecto" */
export const AUTH_JITTER_MIN_MS = 200 as const;
export const AUTH_JITTER_MAX_MS = 700 as const;

/** Regex para sanitizar X-Request-Id (previene header injection) */
export const REQUEST_ID_REGEX = /^[a-zA-Z0-9_\-]{1,64}$/;

// ── Audit ──────────────────────────────────────────────────────────────────────
/** Buffer máximo de logs pendientes antes de que Cloud Logging SDK esté listo */
export const AUDIT_PENDING_LOG_BUFFER_MAX = 100 as const;

// ── Canary ─────────────────────────────────────────────────────────────────────
/** Palabras clave que identifican secretos honeypot */
export const CANARY_PATTERNS = ["canary", "honeypot", "trap", "mcp-admin-trap"] as const;
