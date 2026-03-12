// ── Interfaces Centrales v5 (Titanium) ─────────────────────────────────────────
// Todas las interfaces siguen el principio "defence-in-depth" con campos inmutables.

export interface SecretMetadata {
    readonly secretId: string;
    readonly fullName: string;
    readonly createTime: string;
    readonly labels: Readonly<Record<string, string>>;
    readonly state: string;
    readonly versions: number;
    readonly mcpAccessible: boolean;
}

export interface SecretVersionInfo {
    readonly version: string;
    readonly state: "ENABLED" | "DISABLED" | "DESTROYED";
    readonly createTime: string;
}

export interface ListSecretsResult {
    readonly secrets: readonly SecretMetadata[];
    readonly totalCount: number;
    readonly pageSize: number;
    readonly hasMore: boolean;
    readonly nextPage: string | null;
}

export interface AuditEvent {
    readonly timestamp: string;
    readonly action:
    | "get_secret" | "list_secrets" | "get_metadata" | "list_versions"
    | "create_secret" | "add_version" | "disable_version" | "delete_version"
    | "permission_check" | "notify_rotation" | "synthesize_env"
    | "security_breach" | "rate_limit_exceeded" | "auth_failure";
    readonly secretId: string | null;
    readonly clientId: string;
    readonly projectId: string;
    readonly success: boolean;
    readonly errorCode?: string;
    readonly reason?: string;
    readonly ticketId?: string;
    readonly sourceIp?: string;
}

export interface CacheEntry<T> {
    readonly value: T;
    readonly expiresAt: number;
    readonly iv?: Buffer;
    readonly tag?: Buffer;
    readonly createdAt: number;
}

export interface RateLimitEntry {
    count: number;
    readonly windowStart: number;
}

export interface ServerConfig {
    readonly projectId: string;
    readonly port: number;
    readonly transport: "http" | "stdio";
    readonly authTokens: ReadonlySet<string>;
    readonly allowedOrigins: readonly string[];
    readonly pubSubTopic: string | null;
}

export type CircuitState = "CLOSED" | "OPEN" | "HALF_OPEN";

export interface CircuitBreakerStats {
    readonly state: CircuitState;
    readonly failures: number;
    readonly successes: number;
    readonly lastFailureAt: string | null;
    readonly openSince: string | null;
}

export interface PermissionCheckResult {
    readonly secretId: string;
    readonly allowed: boolean;
    readonly reason: string;
    readonly hasLabel: boolean;
    readonly hasVersion: boolean;
    readonly serverRole: string;
}

export interface EnvSynthesisResult {
    readonly secretIds: readonly string[];
    readonly envContent: string;
    readonly missingIds: readonly string[];
    readonly generatedAt: string;
}

/** Respuesta sanitizada del servidor — nunca incluye stack traces */
export interface ErrorResponse {
    readonly error: string;
    readonly requestId?: string;
    readonly ticketId?: string;
}
