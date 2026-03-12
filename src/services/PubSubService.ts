// ── PubSubService v5 (Titanium) ─────────────────────────────────────────────
// Notificaciones asíncronas de rotación para recarga persistente.

import { PubSub } from "@google-cloud/pubsub";
import { AuditService } from "./AuditService.js";
import { createHash } from "crypto";

export interface RotationEventData {
    readonly secretId: string;
    readonly newVersion: string;
    readonly projectId: string;
    readonly rotatedAt: string;
    readonly rotatedBy: string;
    readonly signature?: string;
}

export class PubSubService {
    private pubsub: PubSub;
    private topicName: string | null;

    constructor(
        topic: string | null,
        projectId: string, // Parámetro de constructor, no propiedad de clase si no se usa después
        private audit: AuditService
    ) {
        this.pubsub = new PubSub({ projectId });
        this.topicName = topic;
    }

    /**
     * Notifica a suscriptores sobre una rotación de secreto.
     * La firma (HMAC o Hash) ayuda a los receptores a verificar origen.
     */
    public async notifyRotation(event: RotationEventData): Promise<void> {
        if (!this.topicName) return;

        try {
            // Firma de integridad ligera para evitar inyección de mensajes de rotación falsos
            const payload: RotationEventData = {
                ...event,
                signature: createHash("sha256")
                    .update(`${event.secretId}:${event.newVersion}:${event.rotatedAt}`)
                    .digest("hex")
            };

            const dataBuffer = Buffer.from(JSON.stringify(payload));
            const messageId = await this.pubsub.topic(this.topicName).publishMessage({
                data: dataBuffer,
                attributes: {
                    action: "secret_rotation",
                    secretId: event.secretId,
                    version: event.newVersion,
                    source: "mcp-vault-v5"
                }
            });

            this.audit.log({
                action: "notify_rotation",
                secretId: event.secretId,
                clientId: event.rotatedBy,
                success: true,
                reason: `PubSub message [${messageId}] published to [${this.topicName}]`
            });
        } catch (err) {
            this.audit.logError(
                "notify_rotation",
                event.secretId,
                event.rotatedBy,
                "PUBSUB_PUBLISH_FAILED",
                String(err)
            );
        }
    }
}
