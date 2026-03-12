# 🛡️ MCP Vault Server v5.0.0 — Titanium Hardening

Servidor MCP de alta seguridad diseñado bajo estándares NIST/OWASP para la gestión crítica de secretos en Google Cloud. **Titanium** representa la cumbre en blindaje operacional y criptográfico.

---

## 💎 Blindaje Titanium (v5.0)

Esta versión introduce protecciones avanzadas para entornos de alta hostilidad:

### 1. 🛡️ Inmunidad Arquitectónica
- **Caché AEAD (AES-256-GCM)**: Secretos cifrados en memoria con integridad autenticada. La llave se rota determinísticamente y se realiza *memory scrubbing* preventivo.
- **Protección TOCTOU**: Validación de etiquetas (`mcp-accessible`) en tiempo real antes de cada acceso al payload, eliminando ataques de carrera.
- **Zero-Information Leakage**: Sanitización agresiva de errores de GCP para evitar fuga de metadatos o topología de infraestructura.

### 2. 🔐 Protocolo Blindado
- **SSE/MCP v1.x+ Modernizado**: Comunicación totalmente alineada con la última especificación del SDK de Model Context Protocol.
- **Security Headers Dinámicos**: CSP estricta, HSTS (2 años), No-Sniff, Frame-Deny y políticas de permisos restrictivas.
- **Auditoría Traceable**: Cada requestID es generado vía CSPRNG y propagado mediante `AsyncLocalStorage` para trazabilidad forense ininterrumpida.

### 3. 💣 Defensa Activa
- **Anti-Canary Traps**: Detección automática de intentos de acceso a patrones de nombres operacionales prohibidos.
- **Circuit Breaker Inteligente**: Evita la degradación en cascada mediante una máquina de estados que monitoriza la salud de Secret Manager.
- **Rate Limiting Contextual**: Límites estrictos basados en identidad y origen para prevenir fuerza bruta y DoS.

---

## 🚀 Despliegue y CI/CD

### Automatizado (GitHub Actions)
La nueva versión incluye un pipeline continuo (`.github/workflows/deploy.yml`). Solo necesitas configurar los siguientes Secrets en tu repositorio:
- `GCP_PROJECT_ID`
- `GCP_SA_EMAIL` (Service Account con permisos de Artifact Registry y Cloud Run)
- `GCP_WID_PROVIDER` (Workload Identity Provider recomendado)

### Manual
```bash
./infra/deploy.sh [PROJECT_ID] [REGION]
```

## 🔌 Herramientas del Servidor (Tools)
El servidor expone herramientas blindadas para:
- **Lectura**: `vault_get_secret`, `vault_get_metadata`, `vault_list_secrets`.
- **Escritura**: `vault_create_secret`, `vault_add_version`, `vault_disable_version`.
- **Contexto**: `vault_synthesize_env` (Generación segura de archivos .env).

---
*Diseñado por Antigravity AI para entornos de misión crítica.*
