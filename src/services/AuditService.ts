// ── AuditService v5 (Titanium) ───────────────────────────────────────────────
// Inmutabilidad persistente. Dual logging (Cloud Run Stderr -> Cloud Logging).
// Integridad garantizada por la inmuatbilidad nativa de GCP logs.

import { AuditEvent } from "../types.js";
import { AUDIT_PENDING_LOG_BUFFER_MAX } from "../constants.js";

type Severity = "INFO" | "WARNING" | "ERROR" | "CRITICAL";

const CRITICAL_ACTIONS = new Set<AuditEvent["action"]>([
    "get_secret",
    "create_secret",
    "add_version",
    "disable_version",
    "security_breach",
    "auth_failure"
]);

const SEVERITY_MAP: Partial<Record<AuditEvent["action"], Severity>> = {
    "security_breach": "CRITICAL",
    "auth_failure": "CRITICAL",
    "disable_version": "WARNING",
    "rate_limit_exceeded": "WARNING",
};

export class AuditService {
    private cloudLogging: any = null;
    private pendingLogs: any[] = [];
    private isInitializing = false;

    constructor(private projectId: string) {
        this._initCloudLogging();
    }

    private _initCloudLogging(): void {
        if (this.isInitializing) return;
        this.isInitializing = true;

        import("@google-cloud/logging").then(({ Logging }: any) => {
            const logging = new Logging({ projectId: this.projectId });
            this.cloudLogging = logging.log("mcp-vault-audit");

            process.stderr.write("✅ Audit: Cloud Logging SDK Ready\n");

            if (this.pendingLogs.length > 0) {
                this._flushPending();
            }
        }).catch((err) => {
            process.stderr.write(`⚠️ Audit Init Fallback: ${String(err)}\n`);
        }).finally(() => {
            this.isInitializing = false;
        });
    }

    private _flushPending(): void {
        const toFlush = [...this.pendingLogs];
        this.pendingLogs = [];

        process.stderr.write(`📦 Audit: Flushing ${toFlush.length} logs to cloud\n`);

        const writePromises = toFlush.map(p =>
            this.cloudLogging.write(this.cloudLogging.entry(p.metadata, p.entry))
        );

        Promise.all(writePromises).catch(err =>
            process.stderr.write(`⚠️ Audit flush error: ${String(err)}\n`)
        );
    }

    public log(event: Omit<AuditEvent, "timestamp" | "projectId">): void {
        const entry: AuditEvent = {
            ...event,
            timestamp: new Date().toISOString(),
            projectId: this.projectId,
        };

        const severity: Severity = SEVERITY_MAP[event.action]
            ?? (event.success ? "INFO" : "WARNING");

        const isCritical = CRITICAL_ACTIONS.has(event.action);

        /**
         * Dual Logging:
         * 1. Stderr: Cloud Run captura stdout/stderr y lo indexa automáticamente.
         *    Esto es vital si el SDK de logging falla o tiene lag.
         */
        process.stderr.write(JSON.stringify({ severity, ...entry }) + "\n");

        /**
         * 2. Cloud Logging SDK: Persistencia avanzada con metadata de severidad
         *    para alertas automáticas en el panel de seguridad de GCP.
         */
        if (isCritical) {
            const metadata = {
                resource: { type: "cloud_run_revision" },
                severity,
            };

            if (this.cloudLogging) {
                this.cloudLogging.write(this.cloudLogging.entry(metadata, entry))
                    .catch((err: unknown) =>
                        process.stderr.write(`⚠️ Audit Cloud Write Fail: ${String(err)}\n`)
                    );
            } else {
                // Buffer preventivo hasta que cargue el SDK dinámico
                this.pendingLogs.push({ metadata, entry });
                if (this.pendingLogs.length > AUDIT_PENDING_LOG_BUFFER_MAX) {
                    process.stderr.write("⚠️ AUDIT BUFFER EXCEEDED — Dropping oldest entry\n");
                    this.pendingLogs.shift();
                }
            }
        }
    }

    public logError(
        action: AuditEvent["action"],
        secretId: string | null,
        clientId: string,
        errorCode: string,
        reason?: string,
    ): void {
        this.log({ action, secretId, clientId, success: false, errorCode, reason });
    }
}
