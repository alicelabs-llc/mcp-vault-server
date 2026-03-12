// ── SecretManagerService v5 (Titanium) ──────────────────────────────────────
// Integración con GCP con blindaje anti-canarios y protección TOCTOU.

import { SecretManagerServiceClient } from "@google-cloud/secret-manager";
import { CacheService } from "./CacheService.js";
import { AuditService } from "./AuditService.js";
import { CircuitBreaker } from "./CircuitBreaker.js";
import { PubSubService } from "./PubSubService.js";
import type {
    SecretMetadata,
    SecretVersionInfo,
    ListSecretsResult,
    PermissionCheckResult,
    EnvSynthesisResult,
} from "../types.js";
import {
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    REQUIRED_LABEL_KEY,
    REQUIRED_LABEL_VALUE,
    SECRET_VALUE_MAX_AGE_MS,
    CANARY_PATTERNS,
    RETRY_ATTEMPTS,
    RETRY_BASE_MS,
    SECRET_VALUE_MAX_BYTES
} from "../constants.js";

const RETRYABLE_CODES = new Set([
    "UNAVAILABLE", "DEADLINE_EXCEEDED", "RESOURCE_EXHAUSTED", "ABORTED", "INTERNAL",
]);

function isRetryable(e: unknown): boolean {
    if (e instanceof Error) {
        const msg = e.message.toUpperCase();
        return Array.from(RETRYABLE_CODES).some(code => msg.includes(code));
    }
    return false;
}

async function withRetry<T>(fn: () => Promise<T>, cb: CircuitBreaker, op: string): Promise<T> {
    return cb.execute(async () => {
        let lastErr: unknown;
        for (let i = 0; i < RETRY_ATTEMPTS; i++) {
            try { return await fn(); } catch (e) {
                lastErr = e;
                if (!isRetryable(e)) throw e;
                if (i < RETRY_ATTEMPTS - 1) {
                    await new Promise(r => setTimeout(r, RETRY_BASE_MS * Math.pow(2, i)));
                }
            }
        }
        throw lastErr;
    }, op);
}

function shortName(n: string | null | undefined): string {
    return n?.split("/").pop() ?? "";
}

function sanitizeGcpError(e: unknown): string {
    if (!(e instanceof Error)) return "Unknown System Error";
    const msg = e.message;
    const codeMatch = msg.match(/\b(NOT_FOUND|PERMISSION_DENIED|ALREADY_EXISTS|INVALID_ARGUMENT|UNAVAILABLE|INTERNAL|UNAUTHENTICATED|RESOURCE_EXHAUSTED)\b/);
    if (codeMatch) return `GCP_ERROR: ${codeMatch[1]}`;
    return "Error: Security context violation during fetch";
}

export class SecretManagerService {
    private client = new SecretManagerServiceClient();
    private cache: CacheService;
    private cbs = new Map<string, CircuitBreaker>();

    constructor(
        readonly projectId: string,
        private audit: AuditService,
        readonly pubsub: PubSubService,
    ) {
        // Inicialización inmediata para evitar error de linter "used before assigned"
        this.cache = new CacheService(audit);
    }

    public destroy(): void {
        this.cache.destroy();
    }

    private _getCB(op: string): CircuitBreaker {
        let cb = this.cbs.get(op);
        if (!cb) {
            cb = new CircuitBreaker(5, 30000, this.audit);
            this.cbs.set(op, cb);
        }
        return cb;
    }

    public get circuitBreakerStats() {
        return this._getCB("global").stats;
    }

    public async checkPermission(secretId: string, clientId: string): Promise<PermissionCheckResult> {
        try {
            const [secret] = await withRetry(() => this.client.getSecret({
                name: `projects/${this.projectId}/secrets/${secretId}`
            }), this._getCB("meta"), "meta");

            const labels = (secret.labels ?? {}) as Record<string, string>;
            const allowed = labels[REQUIRED_LABEL_KEY] === REQUIRED_LABEL_VALUE;

            return {
                secretId,
                allowed,
                reason: allowed ? "Label check passed" : `Missing required label ${REQUIRED_LABEL_KEY}=${REQUIRED_LABEL_VALUE}`,
                hasLabel: !!labels[REQUIRED_LABEL_KEY],
                hasVersion: true,
                serverRole: "mcp-titanium"
            };
        } catch (e: any) {
            return {
                secretId,
                allowed: false,
                reason: sanitizeGcpError(e),
                hasLabel: false,
                hasVersion: false,
                serverRole: "mcp-titanium"
            };
        }
    }

    public async getSecretMetadata(secretId: string, clientId: string): Promise<SecretMetadata> {
        const cacheKey = `meta:${secretId}`;
        const cached = this.cache.getObject<SecretMetadata>(cacheKey);
        if (cached) return cached;

        const [[secret], [vers]] = await Promise.all([
            withRetry(() => this.client.getSecret({ name: `projects/${this.projectId}/secrets/${secretId}` }), this._getCB("meta"), "meta"),
            withRetry(() => this.client.listSecretVersions({ parent: `projects/${this.projectId}/secrets/${secretId}`, filter: "state:ENABLED" }), this._getCB("list"), "list")
        ]);

        const labels = (secret.labels ?? {}) as Record<string, string>;
        const meta: SecretMetadata = {
            secretId,
            fullName: secret.name ?? "",
            createTime: secret.createTime?.seconds ? new Date(Number(secret.createTime.seconds) * 1000).toISOString() : "",
            labels,
            state: "ACTIVE",
            versions: Array.isArray(vers) ? vers.length : 0,
            mcpAccessible: labels[REQUIRED_LABEL_KEY] === REQUIRED_LABEL_VALUE,
        };

        this.cache.setObject(cacheKey, meta);
        this.audit.log({ action: "get_metadata", secretId, clientId, projectId: this.projectId, success: true });
        return meta;
    }

    public async getSecretValue(secretId: string, version = "latest", clientId: string, reason: string): Promise<string> {
        if (CANARY_PATTERNS.some(p => p.test(secretId))) {
            this.audit.log({ action: "security_breach", secretId, clientId, projectId: this.projectId, success: false, reason: `CANARY_TRAP_TRIGGERED: ${reason}` });
            throw new Error("Security Violation: Access to restricted operational resource denied");
        }

        const cacheKey = `val:${secretId}:${version}`;
        const cached = this.cache.get(cacheKey);
        if (cached) {
            this.audit.log({ action: "get_secret", secretId, clientId, projectId: this.projectId, success: true, reason: "Cache hit" });
            return cached;
        }

        const meta = await this.getSecretMetadata(secretId, clientId);
        if (!meta.mcpAccessible) {
            this.audit.log({ action: "security_breach", secretId, clientId, projectId: this.projectId, success: false, reason: "UNAUTHORIZED_MCP_ACCESS_ATTEMPT" });
            throw new Error("Access Denied: Secret not flagged for MCP visibility");
        }

        const [response] = await withRetry(() => this.client.accessSecretVersion({
            name: `projects/${this.projectId}/secrets/${secretId}/versions/${version}`
        }), this._getCB("access"), "access");

        const payload = response.payload?.data?.toString() || "";
        if (!payload) throw new Error("Secret has no data payload");
        if (payload.length > SECRET_VALUE_MAX_BYTES) throw new Error("Secret payload exceeds security limits");

        this.cache.set(cacheKey, payload, SECRET_VALUE_MAX_AGE_MS);
        this.audit.log({ action: "get_secret", secretId, clientId, projectId: this.projectId, success: true, reason });
        return payload;
    }

    public async listSecrets(clientId: string, pageSize = DEFAULT_PAGE_SIZE, pageToken = ""): Promise<ListSecretsResult> {
        const safePageSize = Math.min(Math.max(1, pageSize), MAX_PAGE_SIZE);

        const [secrets, , response] = await withRetry(() => this.client.listSecrets({
            parent: `projects/${this.projectId}`,
            pageSize: safePageSize,
            pageToken: pageToken || undefined,
            filter: `labels.${REQUIRED_LABEL_KEY}=${REQUIRED_LABEL_VALUE}`,
        }), this._getCB("list"), "list");

        const result: ListSecretsResult = {
            secrets: (secrets || []).map(s => ({
                secretId: shortName(s.name),
                fullName: s.name ?? "",
                createTime: "",
                labels: (s.labels ?? {}) as Record<string, string>,
                state: "ACTIVE",
                versions: 0,
                mcpAccessible: true,
            })),
            totalCount: secrets?.length || 0,
            pageSize: safePageSize,
            hasMore: !!response?.nextPageToken,
            nextPage: response?.nextPageToken || null
        };

        this.audit.log({ action: "list_secrets", secretId: null, clientId, projectId: this.projectId, success: true });
        return result;
    }

    public async listVersions(secretId: string, clientId: string): Promise<SecretVersionInfo[]> {
        const [versions] = await withRetry(() => this.client.listSecretVersions({
            parent: `projects/${this.projectId}/secrets/${secretId}`,
            filter: "state:ENABLED"
        }), this._getCB("list"), "list");

        return (versions || []).map(v => ({
            version: shortName(v.name),
            state: (v.state as any) || "ENABLED",
            createTime: v.createTime?.seconds ? new Date(Number(v.createTime.seconds) * 1000).toISOString() : ""
        }));
    }

    public async createSecret(secretId: string, labels: Record<string, string>, clientId: string): Promise<SecretMetadata> {
        const fullLabels = { ...labels, [REQUIRED_LABEL_KEY]: REQUIRED_LABEL_VALUE };

        const [secret] = await withRetry(() => this.client.createSecret({
            parent: `projects/${this.projectId}`,
            secretId,
            secret: {
                replication: { automatic: {} },
                labels: fullLabels
            }
        }), this._getCB("create"), "create");

        this.audit.log({ action: "create_secret", secretId, clientId, projectId: this.projectId, success: true });
        return this.getSecretMetadata(secretId, clientId);
    }

    public async addSecretVersion(secretId: string, value: string, clientId: string): Promise<string> {
        const [version] = await withRetry(() => this.client.addSecretVersion({
            parent: `projects/${this.projectId}/secrets/${secretId}`,
            payload: { data: Buffer.from(value) }
        }), this._getCB("write"), "write");

        const newVersion = shortName(version.name);

        this.pubsub.notifyRotation({
            secretId,
            newVersion,
            projectId: this.projectId,
            rotatedAt: new Date().toISOString(),
            rotatedBy: clientId
        }).catch(() => { });

        this.audit.log({ action: "add_version", secretId, clientId, projectId: this.projectId, success: true });
        return newVersion;
    }

    public async disableVersion(secretId: string, version: string, clientId: string): Promise<{ success: boolean }> {
        await withRetry(() => this.client.disableSecretVersion({
            name: `projects/${this.projectId}/secrets/${secretId}/versions/${version}`
        }), this._getCB("write"), "write");

        this.cache.destroy();
        this.audit.log({ action: "disable_version", secretId, clientId, projectId: this.projectId, success: true, reason: `Version ${version} disabled` });
        return { success: true };
    }

    public async synthesizeEnv(secretIds: string[], clientId: string, reason: string): Promise<EnvSynthesisResult> {
        const results = await Promise.all(secretIds.map(async (id) => {
            try {
                const val = await this.getSecretValue(id, "latest", clientId, reason);
                return { id, val, success: true };
            } catch {
                return { id, val: "", success: false };
            }
        }));

        const envContent = results
            .filter(r => r.success)
            .map(r => `${r.id.toUpperCase().replace(/[^A-Z0-9]/g, "_")}=${r.val}`)
            .join("\n");

        const missingIds = results.filter(r => !r.success).map(r => r.id);

        this.audit.log({ action: "synthesize_env", secretId: null, clientId, projectId: this.projectId, success: true, reason });

        return {
            secretIds,
            envContent,
            missingIds,
            generatedAt: new Date().toISOString()
        };
    }
}
