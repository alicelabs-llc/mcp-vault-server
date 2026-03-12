// ── CacheService v5 (Titanium) ────────────────────────────────────────────────
// Cifrado Authenticated Encryption with Associated Data (AEAD) en memoria.
// Implementa scrubbing de memoria y rotación determinística de llaves.

import {
    createCipheriv,
    createDecipheriv,
    randomBytes,
    createHmac,
    timingSafeEqual
} from "crypto";
import {
    CACHE_TTL_MS,
    CACHE_MAX_ENTRIES,
    CACHE_KEY_ROTATION_MS
} from "../constants.js";
import type { CacheEntry } from "../types.js";
import { AuditService } from "./AuditService.js";

const ALGO = "aes-256-gcm";
const IV_LENGTH = 12; // NIST standard para GCM
const TAG_LENGTH = 16;
const KEY_LENGTH = 32;

let RUNTIME_KEY = randomBytes(KEY_LENGTH);
let HMAC_KEY = randomBytes(KEY_LENGTH);

/**
 * Encapsulación de cifrado con autenticación doble (Encrypt-then-MAC).
 * GCM ya es AEAD, pero el HMAC adicional protege contra debilidades
 * específicas de implementación de GCM en ciertos entornos y asegura
 * la integridad del IV y el Tag antes de tocar la primitiva de cifrado.
 */
function encryptValue(plain: string): { iv: Buffer; tag: Buffer; data: Buffer; mac: Buffer } {
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGO, RUNTIME_KEY, iv, { authTagLength: TAG_LENGTH });

    const data = Buffer.concat([
        cipher.update(plain, "utf8"),
        cipher.final()
    ]);
    const tag = cipher.getAuthTag();

    // HMAC-SHA256 sobre [IV + DATA + TAG]
    const mac = createHmac("sha256", HMAC_KEY)
        .update(Buffer.concat([iv, data, tag]))
        .digest();

    return { iv, tag, data, mac };
}

function decryptValue(enc: { iv: Buffer; tag: Buffer; data: Buffer }): Buffer {
    const decipher = createDecipheriv(ALGO, RUNTIME_KEY, enc.iv, { authTagLength: TAG_LENGTH });
    decipher.setAuthTag(enc.tag);

    return Buffer.concat([
        decipher.update(enc.data),
        decipher.final()
    ]);
}

function verifyMac(entry: { iv: Buffer; tag: Buffer; data: Buffer; mac: Buffer }): boolean {
    const computed = createHmac("sha256", HMAC_KEY)
        .update(Buffer.concat([entry.iv, entry.data, entry.tag]))
        .digest();
    // Timing-safe comparison para evitar ataques de oráculo de padding/mac
    return timingSafeEqual(computed, entry.mac);
}

export class CacheService {
    private static instances = new Set<CacheService>();
    private static _rotationStarted = false;

    private stringStore = new Map<string, CacheEntry<{ iv: Buffer; tag: Buffer; data: Buffer; mac: Buffer }>>();
    private objectStore = new Map<string, CacheEntry<{ iv: Buffer; tag: Buffer; data: Buffer; mac: Buffer }>>();
    private destroyed = false;

    constructor(private audit?: AuditService) {
        CacheService.instances.add(this);
        CacheService._ensureRotationStarted();
    }

    /**
     * Rotación global de claves. Al rotar, todo el caché previo se vuelve ilegible
     * y debe ser purgado. Esto limita la ventana de exposición de una llave filtrada.
     */
    private static _ensureRotationStarted(): void {
        if (this._rotationStarted) return;
        this._rotationStarted = true;

        setInterval(() => {
            // Scrubbing de llaves viejas antes de reemplazarlas
            RUNTIME_KEY.fill(0);
            HMAC_KEY.fill(0);

            RUNTIME_KEY = randomBytes(KEY_LENGTH);
            HMAC_KEY = randomBytes(KEY_LENGTH);

            for (const instance of CacheService.instances) {
                instance.clear();
            }
            process.stderr.write("🔐 Rotation: Keys updated and caches flushed\n");
        }, CACHE_KEY_ROTATION_MS).unref();
    }

    public destroy(): void {
        this.clear();
        CacheService.instances.delete(this);
        this.destroyed = true;
    }

    public clear(): void {
        this.stringStore.clear();
        this.objectStore.clear();
    }

    public setString(key: string, value: string, ttlMs = CACHE_TTL_MS): void {
        if (this.destroyed) return;
        this._evictIfNeeded(this.stringStore);

        const enc = encryptValue(value);
        this.stringStore.set(key, {
            value: enc,
            expiresAt: Date.now() + ttlMs,
            createdAt: Date.now()
        });
    }

    public getString(key: string): string | null {
        if (this.destroyed) return null;
        const entry = this.stringStore.get(key);

        if (!entry) return null;
        if (Date.now() > entry.expiresAt) {
            this.stringStore.delete(key);
            return null;
        }

        // Integrity Check
        if (!verifyMac(entry.value)) {
            this.audit?.log({
                action: "security_breach",
                secretId: key,
                clientId: "cache-system",
                success: false,
                reason: "CACHE_TAMPERING_DETECTED_STRING"
            });
            throw new Error("Security Integrity Violation: Cache compromised");
        }

        const dec = decryptValue(entry.value);
        const result = dec.toString("utf8");

        // Memset/Scrubbing del buffer de texto plano de la memoria de Node
        dec.fill(0);

        return result;
    }

    public getStringAge(key: string): number | null {
        const entry = this.stringStore.get(key);
        if (!entry) return null;
        return entry.expiresAt - Date.now();
    }

    public setObject<T>(key: string, value: T, ttlMs = CACHE_TTL_MS): void {
        if (this.destroyed) return;
        this._evictIfNeeded(this.objectStore);

        const enc = encryptValue(JSON.stringify(value));
        this.objectStore.set(key, {
            value: enc,
            expiresAt: Date.now() + ttlMs,
            createdAt: Date.now()
        });
    }

    public getObject<T>(key: string): T | null {
        if (this.destroyed) return null;
        const entry = this.objectStore.get(key);

        if (!entry) return null;
        if (Date.now() > entry.expiresAt) {
            this.objectStore.delete(key);
            return null;
        }

        if (!verifyMac(entry.value)) {
            this.audit?.log({
                action: "security_breach",
                secretId: key,
                clientId: "cache-system",
                success: false,
                reason: "CACHE_TAMPERING_DETECTED_OBJECT"
            });
            throw new Error("Security Integrity Violation: Cache compromised");
        }

        const dec = decryptValue(entry.value);
        const result = JSON.parse(dec.toString("utf8")) as T;
        dec.fill(0);
        return result;
    }

    public invalidatePrefix(prefix: string): void {
        for (const k of this.stringStore.keys()) if (k.startsWith(prefix)) this.stringStore.delete(k);
        for (const k of this.objectStore.keys()) if (k.startsWith(prefix)) this.objectStore.delete(k);
    }

    public delete(key: string): void {
        this.stringStore.delete(key);
        this.objectStore.delete(key);
    }

    public get stats() {
        return {
            strings: this.stringStore.size,
            objects: this.objectStore.size
        };
    }

    private _evictIfNeeded(store: Map<string, unknown>): void {
        if (store.size >= CACHE_MAX_ENTRIES) {
            // Estrategia FIFO para desalojo
            const toRemove = Math.ceil(CACHE_MAX_ENTRIES * 0.1);
            const keys = store.keys();
            for (let i = 0; i < toRemove; i++) {
                const k = keys.next().value;
                if (k !== undefined) store.delete(k); else break;
            }
        }
    }
}
