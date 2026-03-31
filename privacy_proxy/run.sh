#!/usr/bin/env bashio

# ── Read add-on config ───────────────────────────────────────────────────────
PROXY_PORT=$(bashio::config 'proxy_port')
AGENT_PORT=$(bashio::config 'agent_port')
LOG_LEVEL=$(bashio::config 'log_level')

# Arrays: join with comma
PERSONAL_NAMES=$(bashio::config 'personal_names' | jq -r 'join(",")')
CUSTOM_WORDS=$(bashio::config 'custom_words' | jq -r 'join(",")')
ENTITY_DOMAINS=$(bashio::config 'entity_domains' | jq -r 'join(",")')

# Booleans
REDACT_IPS=$(bashio::config 'redact_ips')
REDACT_MACS=$(bashio::config 'redact_macs')
REDACT_EMAILS=$(bashio::config 'redact_emails')
REDACT_PHONES=$(bashio::config 'redact_phones')
REDACT_GPS=$(bashio::config 'redact_gps')

# ── Export to environment ─────────────────────────────────────────────────────
export PROXY_PORT="${PROXY_PORT}"
# The agent runs on the same host inside the HA add-on network
export AGENT_URL="http://localhost:${AGENT_PORT}"
export PERSONAL_NAMES="${PERSONAL_NAMES}"
export CUSTOM_WORDS="${CUSTOM_WORDS}"
export ENTITY_DOMAINS="${ENTITY_DOMAINS}"
export REDACT_IPS="${REDACT_IPS}"
export REDACT_MACS="${REDACT_MACS}"
export REDACT_EMAILS="${REDACT_EMAILS}"
export REDACT_PHONES="${REDACT_PHONES}"
export REDACT_GPS="${REDACT_GPS}"
export LOG_LEVEL="${LOG_LEVEL}"

# ── Start ────────────────────────────────────────────────────────────────────
bashio::log.info "Starting HA Privacy Proxy on port ${PROXY_PORT}"
bashio::log.info "Forwarding to HA Vibecode Agent on port ${AGENT_PORT}"
bashio::log.info "Redacting: IPs=${REDACT_IPS} MACs=${REDACT_MACS} Emails=${REDACT_EMAILS} GPS=${REDACT_GPS}"

exec python3 -m uvicorn app.main:app \
    --host 0.0.0.0 \
    --port "${PROXY_PORT}" \
    --log-level "${LOG_LEVEL}"
