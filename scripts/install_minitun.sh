#!/usr/bin/env bash
set -euo pipefail

# Standalone minitun installer / migrator.
#
# Wizard-style usage:
#   1. Download this script.
#   2. Edit the variables below, or export a few overrides.
#   3. Run it with `bash install_minitun.sh`.
#
# Example overrides without editing the script:
#   ENDPOINT="edge.example.com:25565"
#   TOKENS_TEXT="key_id_a:secret_a,key_id_b:secret_b"
#   SCOPE="system"
#   bash install_minitun.sh

REPO="${REPO:-hUwUtao/Lure}"
RELEASE="${RELEASE:-latest}"             # latest or a tag like v5.0
ASSET="${ASSET:-minitun-linux-x86_64}"   # default Linux x86_64 release asset
SCOPE="${SCOPE:-system}"                 # user | system
SERVICE_NAME="${SERVICE_NAME:-}"         # blank => auto
BIN_PATH="${BIN_PATH:-}"                 # blank => minitun decides
RUST_LOG="${RUST_LOG:-info}"
ENDPOINT="${ENDPOINT:-}"                 # blank => prompt, unless migrating tunure
TOKENS_TEXT="${TOKENS_TEXT:-}"           # comma/newline/semicolon-separated key:secret list
ENABLE_NOW="${ENABLE_NOW:-1}"            # 1 to enable+start, 0 to just write unit
MIGRATE_TUNURE="${MIGRATE_TUNURE:-1}"    # 1 to auto-discover/migrate old tunure services
KEEP_LEGACY_BIN="${KEEP_LEGACY_BIN:-0}"  # 1 to keep old tunure binary after migration
MIGRATE_MINITUN_USER="${MIGRATE_MINITUN_USER:-1}"  # 1 to migrate old user-scope minitun service
DOWNLOAD_URL="${DOWNLOAD_URL:-}"         # blank => latest-release URL from REPO/ASSET

declare -a TOKENS=()

die() {
    echo "error: $*" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"
}

trim() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

is_true() {
    case "$(trim "$1" | tr '[:upper:]' '[:lower:]')" in
        1|true|yes|on) return 0 ;;
        *) return 1 ;;
    esac
}

sanitize_service_suffix() {
    local raw="$1"
    local out
    out="$(
        printf '%s' "$raw" |
            tr '[:upper:]' '[:lower:]' |
            tr -cs 'a-z0-9' '-' |
            sed 's/^-*//; s/-*$//'
    )"
    if [[ -z "$out" ]]; then
        out="endpoint"
    fi
    printf '%.48s' "$out"
}

parse_token_text() {
    local raw="$1"
    printf '%s' "$raw" |
        tr ',;' '\n' |
        sed 's/^[[:space:]]*//; s/[[:space:]]*$//' |
        sed '/^$/d'
}

read_env_value() {
    local path="$1"
    local key="$2"
    [[ -f "$path" ]] || return 1
    local line
    line="$(grep -E "^${key}=" "$path" | tail -n1 || true)"
    [[ -n "$line" ]] || return 1
    printf '%s' "${line#*=}"
}

scope_flag() {
    if [[ "$SCOPE" == "system" ]]; then
        printf '%s' "--system"
    else
        printf '%s' "--user"
    fi
}

resolve_dirs() {
    if [[ "$SCOPE" == "system" ]]; then
        UNIT_DIR="/etc/systemd/system"
        LEGACY_BIN="/usr/local/bin/tunure"
    else
        local cfg_home="${XDG_CONFIG_HOME:-${HOME:-}/.config}"
        [[ -n "$cfg_home" ]] || die "HOME is required for --user install"
        UNIT_DIR="${cfg_home}/systemd/user"
        LEGACY_BIN="${HOME}/.local/bin/tunure"
    fi
}

parse_legacy_unit_endpoint() {
    local unit="$1"
    local exec_line endpoint
    exec_line="$(sed -n 's/^ExecStart=//p' "$unit" | head -n1)"
    endpoint="$(
        awk '
            {
                for (i = 1; i <= NF; i++) {
                    if ($i == "agent" && i < NF) {
                        print $(i + 1)
                        exit
                    }
                }
            }
        ' <<<"$exec_line"
    )"
    trim "$endpoint"
}

prompt_for_endpoint() {
    [[ -t 0 ]] || die "ENDPOINT is required when no legacy tunure services are found"
    while [[ -z "$ENDPOINT" ]]; do
        read -r -p "Tunnel endpoint (host:port): " ENDPOINT
        ENDPOINT="$(trim "$ENDPOINT")"
    done
}

prompt_for_tokens() {
    [[ -t 0 ]] || die "TOKENS_TEXT is required when no legacy tunure services are found"
    echo "Enter one or more tunnel tokens (key_id:secret). Empty line finishes." >&2
    while true; do
        local token=""
        read -r -p "token> " token
        token="$(trim "$token")"
        if [[ -z "$token" ]]; then
            break
        fi
        TOKENS+=("$token")
    done
    [[ ${#TOKENS[@]} -gt 0 ]] || die "at least one tunnel token is required"
}

download_minitun() {
    local tmp_dir="$1"
    local asset_url
    if [[ -n "$DOWNLOAD_URL" ]]; then
        asset_url="$DOWNLOAD_URL"
    elif [[ "$RELEASE" == "latest" ]]; then
        asset_url="https://github.com/${REPO}/releases/latest/download/${ASSET}"
    else
        asset_url="https://github.com/${REPO}/releases/download/${RELEASE}/${ASSET}"
    fi

    echo "==> downloading ${ASSET} from ${asset_url}" >&2
    curl -fsSL "$asset_url" -o "${tmp_dir}/minitun"
    chmod 0755 "${tmp_dir}/minitun"
}

install_group() {
    local service_name="$1"
    local endpoint="$2"
    local rust_log="$3"
    shift 3
    local -a group_tokens=("$@")
    local -a cmd=(
        "$TMP_DIR/minitun"
        systemd
        install
        "$(scope_flag)"
        --endpoint "$endpoint"
        --rust-log "$rust_log"
    )

    if [[ -n "$service_name" ]]; then
        cmd+=(--name "$service_name")
    fi
    if [[ -n "$BIN_PATH" ]]; then
        cmd+=(--bin-path "$BIN_PATH")
    fi
    if ! is_true "$ENABLE_NOW"; then
        cmd+=(--enable-now=false)
    fi
    for token in "${group_tokens[@]}"; do
        cmd+=(--token "$token")
    done

    echo "==> installing ${service_name:-minitun} for ${endpoint} (${#group_tokens[@]} key(s))" >&2
    "${cmd[@]}"
}

cleanup_legacy_unit() {
    local service_name="$1"
    local unit_path="$2"
    local env_path="$3"

    echo "==> removing legacy ${service_name}.service" >&2
    systemctl "${SYSTEMCTL_ARGS[@]}" disable --now "${service_name}.service" >/dev/null 2>&1 || true
    rm -f "$unit_path"
    if [[ -n "$env_path" ]]; then
        rm -f "$env_path"
    fi
}

[[ "$(uname -s)" == "Linux" ]] || die "this installer currently supports Linux only"
[[ "$(uname -m)" == "x86_64" ]] || die "latest flat release asset '${ASSET}' currently targets linux x86_64 only"

need curl
need install
need mktemp
need systemctl

case "$SCOPE" in
    user|system) ;;
    *) die "SCOPE must be 'user' or 'system'" ;;
esac

resolve_dirs

if [[ -n "$TOKENS_TEXT" ]]; then
    mapfile -t TOKENS < <(parse_token_text "$TOKENS_TEXT")
fi

SYSTEMCTL_ARGS=()
if [[ "$SCOPE" == "user" ]]; then
    SYSTEMCTL_ARGS+=(--user)
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

download_minitun "$TMP_DIR"

if is_true "$MIGRATE_TUNURE"; then
    declare -A GROUP_TOKENS=()
    declare -A GROUP_RUST_LOG=()
    declare -A GROUP_LEGACY_NAMES=()
    shopt -s nullglob
    legacy_units=("${UNIT_DIR}"/tunure*.service)
    shopt -u nullglob

    if [[ ${#legacy_units[@]} -gt 0 ]]; then
        echo "==> found ${#legacy_units[@]} legacy tunure unit(s)" >&2
        for unit_path in "${legacy_units[@]}"; do
            service_name="$(basename "${unit_path%.service}")"
            env_file="$(sed -n 's/^EnvironmentFile=//p' "$unit_path" | head -n1)"
            endpoint="$(parse_legacy_unit_endpoint "$unit_path")"
            token="$(read_env_value "${env_file}" "LURE_TUN_TOKEN" || true)"
            legacy_rust_log="$(read_env_value "${env_file}" "RUST_LOG" || true)"

            if [[ -z "$endpoint" || -z "$token" ]]; then
                echo "warning: skipping ${service_name}; could not resolve endpoint/token" >&2
                continue
            fi

            GROUP_TOKENS["$endpoint"]+=$'\n'"$token"
            if [[ -z "${GROUP_RUST_LOG["$endpoint"]:-}" && -n "$legacy_rust_log" ]]; then
                GROUP_RUST_LOG["$endpoint"]="$legacy_rust_log"
            fi
            GROUP_LEGACY_NAMES["$endpoint"]+=$'\n'"${service_name}|${unit_path}|${env_file}"
        done

        if [[ ${#GROUP_TOKENS[@]} -gt 1 && -n "$SERVICE_NAME" ]]; then
            die "SERVICE_NAME is ambiguous when migrating multiple legacy tunure endpoints"
        fi

        for endpoint in "${!GROUP_TOKENS[@]}"; do
            mapfile -t group_tokens < <(printf '%s\n' "${GROUP_TOKENS["$endpoint"]}" | sed '/^$/d')
            group_rust_log="${GROUP_RUST_LOG["$endpoint"]:-$RUST_LOG}"

            if [[ -n "$SERVICE_NAME" ]]; then
                target_name="$SERVICE_NAME"
            elif [[ ${#GROUP_TOKENS[@]} -eq 1 ]]; then
                target_name="minitun"
            else
                target_name="minitun-$(sanitize_service_suffix "$endpoint")"
            fi

            install_group "$target_name" "$endpoint" "$group_rust_log" "${group_tokens[@]}"

            while IFS='|' read -r legacy_name legacy_unit legacy_env; do
                [[ -n "$legacy_name" ]] || continue
                cleanup_legacy_unit "$legacy_name" "$legacy_unit" "$legacy_env"
            done < <(printf '%s\n' "${GROUP_LEGACY_NAMES["$endpoint"]}" | sed '/^$/d')
        done

        systemctl "${SYSTEMCTL_ARGS[@]}" daemon-reload >/dev/null 2>&1 || true

        if ! is_true "$KEEP_LEGACY_BIN" && [[ -f "$LEGACY_BIN" ]]; then
            echo "==> removing legacy binary ${LEGACY_BIN}" >&2
            rm -f "$LEGACY_BIN"
        fi

        echo "==> migrated legacy tunure installation(s) to minitun" >&2
        exit 0
    fi
fi

if [[ "$SCOPE" == "system" ]] && is_true "$MIGRATE_MINITUN_USER"; then
    # Detect and migrate old user-scope minitun service(s) to system scope
    local user_unit_dir="${XDG_CONFIG_HOME:-${HOME:-}/.config}/systemd/user"
    shopt -s nullglob
    user_units=("${user_unit_dir}"/minitun*.service)
    shopt -u nullglob

    if [[ ${#user_units[@]} -gt 0 ]]; then
        echo "==> found ${#user_units[@]} user-scope minitun unit(s); migrating to system" >&2
        for unit_path in "${user_units[@]}"; do
            svc="$(basename "${unit_path%.service}")"
            systemctl --user disable --now "${svc}.service" >/dev/null 2>&1 || true
            rm -f "$unit_path"
            echo "==> removed user unit: $unit_path" >&2
        done
        systemctl --user daemon-reload >/dev/null 2>&1 || true
    fi

    # Migrate user config to /etc/minitun.toml (if /etc version doesn't exist)
    user_cfg="${XDG_CONFIG_HOME:-${HOME:-}/.config}/minitun.toml"
    if [[ -f "$user_cfg" && ! -f /etc/minitun.toml ]]; then
        echo "==> copying user config $user_cfg → /etc/minitun.toml" >&2
        cp "$user_cfg" /etc/minitun.toml
    fi
fi

prompt_for_endpoint
if [[ ${#TOKENS[@]} -eq 0 ]]; then
    prompt_for_tokens
fi

install_group "$SERVICE_NAME" "$ENDPOINT" "$RUST_LOG" "${TOKENS[@]}"
