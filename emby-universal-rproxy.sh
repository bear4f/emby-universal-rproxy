#!/usr/bin/env bash
# emby-universal-rproxy.sh
# Universal reverse proxy gateway for Emby-like services.
# Client usage:
#   https://YOUR_DOMAIN/<upstream_host:port>/
#   https://YOUR_DOMAIN/https/<upstream_host:port>/
#   https://YOUR_DOMAIN/http/<upstream_host:port>/
#
# IMPORTANT: Enable BasicAuth and/or IP allowlist, otherwise this is an open proxy.
#
# Debian-friendly. Only manages /etc/nginx/{sites-available,sites-enabled} and a map file in /etc/nginx/conf.d/.
# Does NOT overwrite /etc/nginx/nginx.conf (to avoid QUIC/http3 directive incompatibility).

set -euo pipefail

SITES_AVAIL="/etc/nginx/sites-available"
SITES_ENAB="/etc/nginx/sites-enabled"
CONF_PREFIX="emby-gw-"
MAP_CONF="/etc/nginx/conf.d/emby-gw-map.conf"
SNIP_CONF="/etc/nginx/snippets/emby-gw-locations.conf"
HTPASSWD_PATH="/etc/nginx/.htpasswd-emby-gw"
BACKUP_ROOT="/root"
TOOL_NAME="emby-universal-rproxy"

need_root() { [[ "${EUID}" -eq 0 ]] || { echo "Run as root: sudo bash $0"; exit 1; }; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }

prompt() {
  local __var="$1" __msg="$2" __def="${3:-}"
  local input=""
  if [[ -n "$__def" ]]; then
    read -r -p "$__msg [$__def]: " input
    input="${input:-$__def}"
  else
    read -r -p "$__msg: " input
  fi
  printf -v "$__var" "%s" "$input"
}

yesno() {
  local __var="$1" __msg="$2" __def="${3:-y}"
  local input=""
  read -r -p "$__msg (y/n) [$__def]: " input
  input="${input:-$__def}"
  input="$(echo "$input" | tr '[:upper:]' '[:lower:]')"
  [[ "$input" == "y" || "$input" == "yes" ]] && printf -v "$__var" "y" || printf -v "$__var" "n"
}

strip_scheme() {
  local s="$1"
  s="${s#http://}"
  s="${s#https://}"
  echo "$s"
}

sanitize_name() { echo "$1" | tr -cd '[:alnum:]._-' | sed 's/^\.*//;s/\.*$//'; }

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null
  apt-get install -y "$@" >/dev/null
}

ensure_deps() {
  # apache2-utils provides htpasswd
  apt_install nginx curl ca-certificates rsync apache2-utils openssl
}


ensure_certbot() {
  apt_install certbot python3-certbot-nginx
}

ensure_htpasswd() {
  if ! has_cmd htpasswd; then
    apt_install apache2-utils
  fi
}

backup_nginx() {
  local ts dir
  ts="$(date +%Y%m%d_%H%M%S)"
  dir="${BACKUP_ROOT}/nginx-backup-${ts}"
  mkdir -p "$dir/nginx"
  rsync -a /etc/nginx/ "$dir/nginx/"
  echo "$dir"
}

restore_nginx() {
  local dir="$1"
  rsync -a --delete "$dir/nginx/" /etc/nginx/
}

validate_nginx() {
  local dumpfile="$1"
  nginx -t >/dev/null
  nginx -T >"$dumpfile" 2>/dev/null
}

reload_nginx() {
  systemctl enable nginx >/dev/null 2>&1 || true
  systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1 || true
}

apply_with_rollback() {
  local backup_dir="$1"
  local dumpfile="$2"

  set +e
  validate_nginx "$dumpfile"
  local rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    echo "ERROR: nginx validation failed (nginx -t/-T). Rolling back..."
    echo "nginx -T output saved to: $dumpfile"
    restore_nginx "$backup_dir"
    nginx -t >/dev/null 2>&1 || true
    reload_nginx
    echo "Rollback done. Nginx restored."
    return 1
  fi

  reload_nginx
  return 0
}

certbot_enable_tls() {
  local domain="$1"
  local email="$2"
  ensure_certbot
  certbot --nginx -d "$domain" --agree-tos -m "$email" --non-interactive --redirect
}

conf_path_for_domain() {
  local domain="$1"
  local safe; safe="$(sanitize_name "$domain")"
  echo "${SITES_AVAIL}/${CONF_PREFIX}${safe}.conf"
}

enabled_path_for_domain() {
  local domain="$1"
  local safe; safe="$(sanitize_name "$domain")"
  echo "${SITES_ENAB}/${CONF_PREFIX}${safe}.conf"
}

random_pass() {
  # 20 chars (hex), no SIGPIPE issues under pipefail
  openssl rand -hex 10 2>/dev/null
}

write_map_conf() {
  mkdir -p /etc/nginx/conf.d
  cat > "$MAP_CONF" <<'EOL'
# Managed by emby-universal-rproxy
# Extract upstream host (no port) for Host header to avoid 421 on CF-backed origins.
map $up_target $up_host_only {
    default                              $up_target;
    ~^\[(?<h>[A-Fa-f0-9:.]+)\](:\d+)?$   [$h];
    ~^(?<h>[^:]+)(:\d+)?$                $h;
}
EOL
}

write_locations_snippet() {
  local enable_basicauth="$1"
  local enable_ip_whitelist="$2"
  local whitelist_csv="$3"

  mkdir -p /etc/nginx/snippets

  # Build auth snippet
  local auth_snip=""
  if [[ "$enable_basicauth" == "y" ]]; then
    auth_snip=$'    auth_basic "Restricted";\n    auth_basic_user_file /etc/nginx/.htpasswd-emby-gw;\n'
  fi

  # Build allowlist snippet
  local allow_snip=""
  if [[ "$enable_ip_whitelist" == "y" ]]; then
    local csv="${whitelist_csv// /}"
    IFS=',' read -r -a arr <<<"$csv"
    for cidr in "${arr[@]}"; do
      [[ -z "$cidr" ]] && continue
      allow_snip+="    allow ${cidr};\n"
    done
    allow_snip+="    deny all;\n"
  fi

  cat > "$SNIP_CONF" <<'EOL'
# Managed by emby-universal-rproxy
# Common proxy settings for Emby (websocket + range + long timeouts)

map $http_upgrade $connection_upgrade {
  default upgrade;
  ""      close;
}

proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection $connection_upgrade;
proxy_set_header Range $http_range;
proxy_set_header If-Range $http_if_range;

proxy_buffering off;
proxy_request_buffering off;
proxy_read_timeout 3600s;
proxy_send_timeout 3600s;
client_max_body_size 500m;

# For variable upstream, Nginx needs a resolver.
# Prefer local resolver if present; otherwise public resolvers.
resolver 127.0.0.1 1.1.1.1 8.8.8.8 valid=60s;
resolver_timeout 5s;

# /http/<target>/...
location ~ ^/http/(?<up_target>[A-Za-z0-9.\-_\[\]:]+)(?<up_rest>/.*)?$ {
    set $up_scheme http;
    if ($up_rest = "") { set $up_rest "/"; }

    # AUTH_SNIP
    # ALLOW_SNIP

    proxy_set_header Host $up_host_only;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    proxy_ssl_server_name on;

    proxy_pass $up_scheme://$up_target$up_rest$is_args$args;
}

# /https/<target>/...
location ~ ^/https/(?<up_target>[A-Za-z0-9.\-_\[\]:]+)(?<up_rest>/.*)?$ {
    set $up_scheme https;
    if ($up_rest = "") { set $up_rest "/"; }

    # AUTH_SNIP
    # ALLOW_SNIP

    proxy_set_header Host $up_host_only;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    proxy_ssl_server_name on;

    proxy_pass $up_scheme://$up_target$up_rest$is_args$args;
}

# Default: /<target>/...  (scheme defaults to https)
location ~ ^/(?<up_target>[A-Za-z0-9.\-_\[\]:]+)(?<up_rest>/.*)?$ {
    set $up_scheme https;
    if ($up_rest = "") { set $up_rest "/"; }

    # AUTH_SNIP
    # ALLOW_SNIP

    proxy_set_header Host $up_host_only;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    proxy_ssl_server_name on;

    proxy_pass $up_scheme://$up_target$up_rest$is_args$args;
}
EOL

  # Inject snippets
  # Use a safe replacement without non-ascii
  perl -0777 -i -pe "s/# AUTH_SNIP/$auth_snip/g; s/# ALLOW_SNIP/$allow_snip/g" "$SNIP_CONF"
}

write_gateway_site_conf() {
  local domain="$1"

  local conf; conf="$(conf_path_for_domain "$domain")"
  local enabled; enabled="$(enabled_path_for_domain "$domain")"

  cat > "$conf" <<EOL
# ${TOOL_NAME}: Universal Gateway for ${domain}
# Managed by ${TOOL_NAME}

server {
  listen 80;
  listen [::]:80;
  server_name ${domain};

  location ^~ /.well-known/acme-challenge/ {
    root /var/www/html;
    try_files \$uri =404;
  }

  location = / {
    default_type text/plain;
    return 200 "OK\n\nUse in Emby client as:\n  https://${domain}/<upstream_host:port>\n  https://${domain}/https/<upstream_host:port>\n  https://${domain}/http/<upstream_host:port>\n\nExample:\n  https://${domain}/plus.younoyes.com:443\n";
  }

  include /etc/nginx/snippets/emby-gw-locations.conf;
}
EOL

  ln -sf "$conf" "$enabled"
  rm -f "${SITES_ENAB}/default" >/dev/null 2>&1 || true
}

print_usage() {
  local domain="$1"
  local ssl="$2"
  local user="$3"
  local pass="$4"

  local base="http://${domain}"
  [[ "$ssl" == "y" ]] && base="https://${domain}"

  echo
  echo "==== Universal proxy usage ===="
  echo "Emby server address examples:"
  echo "  ${base}/plus.younoyes.com:443"
  echo "  ${base}/https/plus.younoyes.com:443"
  echo "  ${base}/http/1.2.3.4:8096"
  echo
  if [[ -n "$user" ]]; then
    echo "BasicAuth enabled:"
    echo "  username: $user"
    echo "  password: $pass"
  else
    echo "WARNING: BasicAuth disabled. Do NOT expose this publicly."
  fi
  echo "==============================="
  echo
}

action_install_update() {
  ensure_deps

  local DOMAIN ENABLE_SSL EMAIL
  local ENABLE_BASICAUTH BASIC_USER BASIC_PASS
  local ENABLE_IPWL IPWL

  prompt DOMAIN "Gateway domain (e.g. autoemby.example.com; domain only)" 
  DOMAIN="$(strip_scheme "$DOMAIN")"
  [[ -n "$DOMAIN" ]] || { echo "Domain cannot be empty"; return 1; }

  yesno ENABLE_SSL "Enable Let's Encrypt TLS for the gateway domain" "y"
  EMAIL="admin@${DOMAIN}"
  [[ "$ENABLE_SSL" == "y" ]] && prompt EMAIL "Let's Encrypt email" "$EMAIL"

  yesno ENABLE_BASICAUTH "Enable BasicAuth (recommended)" "y"
  BASIC_USER="emby"
  BASIC_PASS=""
  if [[ "$ENABLE_BASICAUTH" == "y" ]]; then
    prompt BASIC_USER "BasicAuth username" "emby"
    BASIC_PASS="$(random_pass)"
    prompt BASIC_PASS "BasicAuth password (empty = auto-generated)" "$BASIC_PASS"
    ensure_htpasswd
    ensure_htpasswd
    htpasswd -bc "$HTPASSWD_PATH" "$BASIC_USER" "$BASIC_PASS" >/dev/null
  fi

  yesno ENABLE_IPWL "Enable IP allowlist (optional)" "n"
  IPWL=""
  if [[ "$ENABLE_IPWL" == "y" ]]; then
    prompt IPWL "Allowlist CSV (e.g. 1.2.3.4/32,5.6.7.8/32)"
    [[ -n "$IPWL" ]] || { echo "Allowlist cannot be empty"; return 1; }
  fi

  echo
  echo "Config summary:"
  echo "  domain: $DOMAIN"
  echo "  tls: $ENABLE_SSL"
  echo "  basicauth: $ENABLE_BASICAUTH"
  echo "  allowlist: $ENABLE_IPWL"
  echo

  ensure_deps

  local backup dump
  backup="$(backup_nginx)"
  dump="$(mktemp)"
  trap 'rm -f "$dump"' RETURN

  write_map_conf
  write_locations_snippet "$ENABLE_BASICAUTH" "$ENABLE_IPWL" "$IPWL"
  write_gateway_site_conf "$DOMAIN"

  apply_with_rollback "$backup" "$dump" || return 1

  if [[ "$ENABLE_SSL" == "y" ]]; then
    set +e
    certbot_enable_tls "$DOMAIN" "$EMAIL"
    local rc=$?
    set -e
    if [[ $rc -ne 0 ]]; then
      echo "ERROR: certbot failed. Rolling back..."
      restore_nginx "$backup"
      reload_nginx
      return 1
    fi
    apply_with_rollback "$backup" "$dump" || return 1
  fi

  echo "DONE. Gateway is live on: $DOMAIN"
  if [[ "$ENABLE_BASICAUTH" == "y" ]]; then
    print_usage "$DOMAIN" "$ENABLE_SSL" "$BASIC_USER" "$BASIC_PASS"
  else
    print_usage "$DOMAIN" "$ENABLE_SSL" "" ""
  fi
}

action_status() {
  echo "=== Status ==="
  ls -l "${SITES_AVAIL}/${CONF_PREFIX}"*.conf 2>/dev/null || echo "(no gateway site found)"
  echo
  nginx -t || true
  echo
  systemctl status nginx --no-pager || true
  echo
  [[ -f "$MAP_CONF" ]] && echo "Map file: $MAP_CONF (exists)" || echo "Map file: $MAP_CONF (missing)"
  [[ -f "$SNIP_CONF" ]] && echo "Snippet:  $SNIP_CONF (exists)" || echo "Snippet:  $SNIP_CONF (missing)"
}

action_change_auth() {
  local user pass
  if [[ ! -f "$HTPASSWD_PATH" ]]; then
    echo "No htpasswd file found: $HTPASSWD_PATH"
    echo "Enable BasicAuth via Install/Update first."
    return 1
  fi
  ensure_deps
  ensure_htpasswd
  prompt user "New BasicAuth username" "emby"
  pass="$(random_pass)"
  prompt pass "New BasicAuth password (empty = auto-generated)" "$pass"
  ensure_htpasswd
  htpasswd -bc "$HTPASSWD_PATH" "$user" "$pass" >/dev/null
  reload_nginx
  echo "Updated BasicAuth:"
  echo "  username: $user"
  echo "  password: $pass"
}

action_uninstall() {
  local DOMAIN
  prompt DOMAIN "Gateway domain to uninstall"
  DOMAIN="$(strip_scheme "$DOMAIN")"

  local conf enabled
  conf="$(conf_path_for_domain "$DOMAIN")"
  enabled="$(enabled_path_for_domain "$DOMAIN")"

  echo "Will remove:"
  echo "  $conf"
  echo "  $enabled"
  echo "  $MAP_CONF"
  echo "  $SNIP_CONF"
  echo "  $HTPASSWD_PATH"
  echo
  yesno OK "Confirm uninstall" "n"
  [[ "$OK" == "y" ]] || { echo "Cancelled"; return 0; }

  ensure_deps
  local backup dump
  backup="$(backup_nginx)"
  dump="$(mktemp)"
  trap 'rm -f "$dump"' RETURN

  rm -f "$enabled" "$conf" "$MAP_CONF" "$SNIP_CONF" "$HTPASSWD_PATH" 2>/dev/null || true
  apply_with_rollback "$backup" "$dump" || true
  echo "Uninstalled. Backup: $backup"
  echo "If you want to delete TLS cert: certbot delete --cert-name $DOMAIN"
}

menu() {
  local os_name="unknown" os_ver="unknown" os_code="unknown"
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    os_name="${NAME:-unknown}"
    os_ver="${VERSION_ID:-unknown}"
    os_code="${VERSION_CODENAME:-${DEBIAN_CODENAME:-unknown}}"
  fi

  echo "=== ${TOOL_NAME} (Universal Emby Gateway) ==="
  echo "OS: ${os_name} / ${os_ver} / ${os_code}"
  echo "Tip: Enable BasicAuth or IP allowlist to avoid open proxy."
  echo

  while true; do
    echo "========== Menu =========="
    echo "1) Install/Update gateway"
    echo "2) Status"
    echo "3) Change BasicAuth"
    echo "4) Uninstall"
    echo "0) Exit"
    echo "=========================="
    read -r -p "Select: " c
    case "$c" in
      1) action_install_update ;;
      2) action_status ;;
      3) action_change_auth ;;
      4) action_uninstall ;;
      0) exit 0 ;;
      *) echo "Invalid option" ;;
    esac
  done
}

need_root
menu

