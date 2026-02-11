#!/usr/bin/env bash
# emby-universal-rproxy.sh
# Universal reverse proxy gateway for Emby-like services:
#   Client uses: https://YOUR_DOMAIN/<upstream_host:port>/   (default upstream scheme=https)
#   or:          https://YOUR_DOMAIN/http/<upstream_host:port>/
#                https://YOUR_DOMAIN/https/<upstream_host:port>/
#
# Security: This is effectively a "gateway proxy". DO NOT run without authentication.
# Features:
# - Menu driven: install/update gateway, view status, change auth, uninstall
# - Debian-friendly dependency install
# - nginx -t/-T validate + automatic rollback
# - Let's Encrypt via certbot (optional)
# - Proper headers (avoid 421): proxy_set_header Host $up_host_only; (derived from upstream)
set -euo pipefail

# -------------------- config --------------------
SITES_AVAIL="/etc/nginx/sites-available"
SITES_ENAB="/etc/nginx/sites-enabled"
CONF_PREFIX="emby-gw-"
MAP_CONF="/etc/nginx/conf.d/emby-gw-map.conf"
HTPASSWD_PATH="/etc/nginx/.htpasswd-emby-gw"
BACKUP_ROOT="/root"
TOOL_NAME="emby-universal-rproxy"
# ------------------------------------------------

need_root() { [[ "${EUID}" -eq 0 ]] || { echo "è¯·ç¨ root è¿è¡ï¼sudo bash $0"; exit 1; }; }
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

sanitize_name() { echo "$1" | tr -cd '[:alnum:]._-' | sed 's/^\.*//;s/\.*$//'; }

strip_scheme() {
  local s="$1"
  s="${s#http://}"
  s="${s#https://}"
  echo "$s"
}

is_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  (( p >= 1 && p <= 65535 )) || return 1
  return 0
}

os_info() {
  local name="unknown" ver="unknown" codename="unknown"
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    name="${NAME:-unknown}"
    ver="${VERSION_ID:-unknown}"
    codename="${VERSION_CODENAME:-${DEBIAN_CODENAME:-unknown}}"
  fi
  echo "$name|$ver|$codename"
}

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null
  apt-get install -y "$@" >/dev/null
}

ensure_deps() {
  apt_install nginx curl ca-certificates rsync apache2-utils openssl
}

ensure_certbot() {
  apt_install certbot python3-certbot-nginx
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
    echo "â nginx æ ¡éªå¤±è´¥ï¼nginx -t/-Tï¼ï¼å¼å§åæ»..."
    echo "---- nginx -T è¾åºï¼å«éè¯¯ï¼å·²ä¿å­ï¼$dumpfile ----"
    restore_nginx "$backup_dir"
    nginx -t >/dev/null 2>&1 || true
    reload_nginx
    echo "â å·²åæ»å¹¶æ¢å¤ Nginxã"
    return 1
  fi

  reload_nginx
  return 0
}

certbot_enable_tls() {
  local domain="$1"
  local email="$2"

  ensure_certbot
  # Use installer safely: requires server_name block for domain exists.
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
  # 20 chars, avoid pipefail+SIGPIPE issues
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 10 2>/dev/null
  else
    # fallback: date+pid+random (not crypto-strong but avoids SIGPIPE)
    echo "$(date +%s)$$$RANDOM$RANDOM" | sha256sum | awk '{print $1}' | cut -c1-20
  fi
}

write_map_conf() {
  # This file is in http{} context via /etc/nginx/conf.d/*.conf include.
  cat > "$MAP_CONF" <<'EOL'
# Managed by emby-universal-rproxy
# Extract upstream host (without port) for Host header to avoid 421 on CF-backed origins.
#
# $up_target comes from regex capture "target" in locations below; examples:
#   plus.younoyes.com:443
#   emby.home.net:8096
#   [2400:xxxx::1]:8920
#
# Output:
#   $up_host_only => plus.younoyes.com  / emby.home.net / [2400:xxxx::1]
map $up_target $up_host_only {
    default                         $up_target;
    ~^\[(?<h>[A-Fa-f0-9:.]+)\](:\d+)?$  [$h];
    ~^(?<h>[^:]+)(:\d+)?$           $h;
}
EOL
}

write_gateway_site_conf() {
  local domain="$1"
  local enable_basicauth="$2"
  local basic_user="$3"
  local basic_pass="$4"
  local enable_ip_whitelist="$5"
  local whitelist_csv="$6"

  local conf; conf="$(conf_path_for_domain "$domain")"
  local enabled; enabled="$(enabled_path_for_domain "$domain")"

  local auth_snip=""
  if [[ "$enable_basicauth" == "y" ]]; then
    htpasswd -bc "$HTPASSWD_PATH" "$basic_user" "$basic_pass" >/dev/null
    auth_snip=$'auth_basic "Restricted";\n        auth_basic_user_file '"$HTPASSWD_PATH"$';\n'
  fi

  local allow_snip=""
  if [[ "$enable_ip_whitelist" == "y" ]]; then
    # whitelist_csv: "1.2.3.4/32,5.6.7.8/32"
    local csv="${whitelist_csv// /}"
    IFS=',' read -r -a arr <<<"$csv"
    allow_snip="        # IP ç½ååï¼å¯éï¼\n"
    for cidr in "${arr[@]}"; do
      [[ -z "$cidr" ]] && continue
      allow_snip+="        allow ${cidr};\n"
    done
    allow_snip+="        deny all;\n"
  fi

  # NOTE: We purposely do NOT touch /etc/nginx/nginx.conf to avoid QUIC/http3 conflicts.
  # We only manage a site conf + an http-level map in conf.d.
  cat > "$conf" <<EOL
# ${TOOL_NAME}: Universal Gateway for ${domain}
# Managed by ${TOOL_NAME}
# META domain=${domain} basicauth=${enable_basicauth} ip_whitelist=${enable_ip_whitelist}

# -------------------- HTTP entry (80) --------------------
server {
    listen 80;
    listen [::]:80;
    server_name ${domain};

    # Let's Encrypt challenge (certbot)
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/html;
        try_files \$uri =404;
    }

    # Friendly landing page
    location = / {
        default_type text/plain;
        return 200 "OK\\n\\nUse in Emby client as:\\n  https://${domain}/<upstream_host:port>\\n  https://${domain}/https/<upstream_host:port>\\n  https://${domain}/http/<upstream_host:port>\\n\\nExample:\\n  https://${domain}/plus.younoyes.com:443\\n  https://${domain}/https/plus.younoyes.com:443\\n";
    }

    # NOTE: We do NOT force redirect here because certbot --redirect will handle it when enabled.
    # Universal gateway locations:
    include /etc/nginx/snippets/emby-gw-locations.conf;
}
EOL

  # Write reusable locations snippet (so certbot can later insert 443 block without breaking regex)
  mkdir -p /etc/nginx/snippets
  cat > /etc/nginx/snippets/emby-gw-locations.conf <<'EOL'
# Managed by emby-universal-rproxy
# Security: keep auth enabled, otherwise this becomes an open proxy.

# common proxy settings (Emby needs websockets + range + long timeouts)
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

# For variable upstream, Nginx needs resolver:
resolver 127.0.0.1 1.1.1.1 8.8.8.8 valid=60s;
resolver_timeout 5s;

# Prevent proxying to weird schemes; only http/https are supported by our routing.
# (CONNECT method is not supported by nginx http proxy anyway.)
if ($request_method !~ ^(GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH)$) { return 405; }

# If you want to restrict to your own devices, enable BasicAuth and/or IP allowlist in the script.

# /http/<target>/...
location ~ ^/http/(?<up_target>[A-Za-z0-9.\-_\[\]:]+)(?<up_rest>/.*)?$ {
    set $up_scheme http;
    if ($up_rest = "") { set $up_rest "/"; }

    # Optional auth / allowlist injected by main config via include order:
    # (kept here so certbot-inserted 443 block can reuse)
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

  # Inject auth/allow snippets into the locations file (simple text replace placeholders)
  local snip_file="/etc/nginx/snippets/emby-gw-locations.conf"
  local auth_replace=""
  local allow_replace=""

  if [[ "$enable_basicauth" == "y" ]]; then
    auth_replace=$'auth_basic "Restricted";\n    auth_basic_user_file /etc/nginx/.htpasswd-emby-gw;\n'
  fi
  if [[ "$enable_ip_whitelist" == "y" ]]; then
    # Build allow/deny snippet
    local csv="${whitelist_csv// /}"
    IFS=',' read -r -a arr <<<"$csv"
    allow_replace=""
    for cidr in "${arr[@]}"; do
      [[ -z "$cidr" ]] && continue
      allow_replace+=$"allow ${cidr};\n"
    done
    allow_replace+=$"deny all;\n"
  fi

  # Replace placeholders (each occurrence)
  # Use perl for multiline safety.
  perl -0777 -i -pe "s/# AUTH_SNIP/${auth_replace//\\/\\\\}/g; s/# ALLOW_SNIP/${allow_replace//\\/\\\\}/g" "$snip_file"

  ln -sf "$conf" "$enabled"
  rm -f "${SITES_ENAB}/default" >/dev/null 2>&1 || true
}

print_usage_hint() {
  local domain="$1"
  local enable_ssl="$2"
  local basic_user="$3"
  local basic_pass="$4"

  local base="http://${domain}"
  [[ "$enable_ssl" == "y" ]] && base="https://${domain}"

  echo
  echo "================ éç¨åä»£ä½¿ç¨æ¹æ³ ================"
  echo "å¨ Emby å®¢æ·ç«¯ãæå¡å¨å°åãå¡«ï¼"
  echo "  ${base}/<æºç«ååæIP:ç«¯å£>"
  echo "  ï¼é»è®¤æ https åæºï¼"
  echo
  echo "ä¹æ¯ææ¾å¼æå®åè®®ï¼"
  echo "  ${base}/https/<æºç«ååæIP:ç«¯å£>"
  echo "  ${base}/http/<æºç«ååæIP:ç«¯å£>"
  echo
  echo "ä¾å­ï¼"
  echo "  ${base}/plus.younoyes.com:443"
  echo "  ${base}/https/plus.younoyes.com:443"
  echo "  ${base}/http/1.2.3.4:8096"
  echo
  echo "è®¤è¯ï¼"
  if [[ -n "$basic_user" ]]; then
    echo "  å·²å¯ç¨ BasicAuthï¼ç¨æ·å ${basic_user}"
    echo "  å¯ç ï¼${basic_pass}"
  else
    echo "  â ï¸ æªå¯ç¨ BasicAuthï¼å¼ºçä¸å»ºè®®å¬ç½è¿æ ·è·ï¼ä¼åæå¼æ¾ä»£çï¼"
  fi
  echo "=================================================="
  echo
}

action_install_or_update() {
  local DOMAIN ENABLE_SSL EMAIL
  local ENABLE_BASICAUTH BASIC_USER BASIC_PASS
  local ENABLE_IPWL IPWL

  prompt DOMAIN "ä½ çå¥å£ååï¼ä¾å¦ emby.bear4f.deï¼åªå¡«ååï¼ä¸è¦ https://ï¼"
  DOMAIN="$(strip_scheme "$DOMAIN")"
  [[ -n "$DOMAIN" ]] || { echo "ååä¸è½ä¸ºç©º"; return 1; }

  yesno ENABLE_SSL "ä¸ºå¥å£ååç³è¯· Let's Encryptï¼å¯ç¨ 443 å¹¶ 80->443ï¼" "y"
  EMAIL="admin@${DOMAIN}"
  [[ "$ENABLE_SSL" == "y" ]] && prompt EMAIL "è¯ä¹¦é®ç®±" "$EMAIL"

  yesno ENABLE_BASICAUTH "å¯ç¨ BasicAuthï¼å¼ºçå»ºè®®å¼å¯ï¼" "y"
  BASIC_USER="emby"
  BASIC_PASS=""
  if [[ "$ENABLE_BASICAUTH" == "y" ]]; then
    prompt BASIC_USER "BasicAuth ç¨æ·å" "emby"
    BASIC_PASS="$(random_pass)"
    prompt BASIC_PASS "BasicAuth å¯ç ï¼çç©ºå°èªå¨çæï¼" "$BASIC_PASS"
  fi

  yesno ENABLE_IPWL "å¯ç¨ IP ç½ååï¼å¯éï¼æ´å®å¨ï¼" "n"
  IPWL=""
  if [[ "$ENABLE_IPWL" == "y" ]]; then
    prompt IPWL "ç½ååï¼éå·åéï¼å¦ 1.2.3.4/32,5.6.7.8/32ï¼"
    [[ -n "$IPWL" ]] || { echo "ç½ååä¸è½ä¸ºç©º"; return 1; }
  fi

  echo
  echo "---- éç½®ç¡®è®¤ ----"
  echo "å¥å£åå:    $DOMAIN"
  echo "å¥å£ HTTPS:  $ENABLE_SSL"
  echo "BasicAuth:   $ENABLE_BASICAUTH"
  echo "IP ç½åå:   $ENABLE_IPWL ${IPWL:+($IPWL)}"
  echo "------------------"
  echo

  ensure_deps

  local backup dump
  backup="$(backup_nginx)"
  dump="$(mktemp)"
  trap 'rm -f "$dump"' RETURN

  # write http-level map
  write_map_conf

  # write site conf + locations snippet
  write_gateway_site_conf "$DOMAIN" "$ENABLE_BASICAUTH" "$BASIC_USER" "$BASIC_PASS" "$ENABLE_IPWL" "$IPWL"

  # validate + reload (rollback on fail)
  apply_with_rollback "$backup" "$dump" || return 1

  # TLS (optional) then validate again
  if [[ "$ENABLE_SSL" == "y" ]]; then
    set +e
    certbot_enable_tls "$DOMAIN" "$EMAIL"
    local rc_cert=$?
    set -e
    if [[ $rc_cert -ne 0 ]]; then
      echo "â certbot éç½®å¤±è´¥ï¼åæ»..."
      restore_nginx "$backup"
      reload_nginx
      return 1
    fi
    apply_with_rollback "$backup" "$dump" || return 1
  fi

  echo "â å·²çæï¼$DOMAIN"
  echo "ç«ç¹éç½®ï¼$(conf_path_for_domain "$DOMAIN")"
  echo "MAP éç½®ï¼$MAP_CONF"
  echo "å¤ä»½ç®å½ï¼$backup"
  echo

  if [[ "$ENABLE_BASICAUTH" == "y" ]]; then
    print_usage_hint "$DOMAIN" "$ENABLE_SSL" "$BASIC_USER" "$BASIC_PASS"
  else
    print_usage_hint "$DOMAIN" "$ENABLE_SSL" "" ""
  fi

  echo "æç¤ºï¼"
  echo "  - è¿æ¯âéç¨ç½å³åä»£âï¼å¡å¿å¼å¯ BasicAuth æ IP ç½ååï¼å¦åç­äºå¼æ¾ä»£çã"
  echo "  - åæºé»è®¤ httpsï¼å¦ææºç«æ¯ httpï¼è¯·ç¨ /http/<host:port>ã"
}

action_status() {
  echo "=== ${TOOL_NAME} ç¶æ ==="
  ls -l "${SITES_AVAIL}/${CONF_PREFIX}"*.conf 2>/dev/null || echo "ï¼æªæ¾å°ç«ç¹éç½®ï¼"
  echo
  echo "nginx -tï¼"
  nginx -t || true
  echo
  echo "nginx ç¶æï¼"
  systemctl status nginx --no-pager || true
  echo
  if [[ -f "$MAP_CONF" ]]; then
    echo "MAP éç½®ï¼$MAP_CONFï¼å­å¨ï¼"
  else
    echo "MAP éç½®ï¼$MAP_CONFï¼ä¸å­å¨ï¼"
  fi
}

action_change_auth() {
  local user pass
  if [[ ! -f "$HTPASSWD_PATH" ]]; then
    echo "æªæ¾å° $HTPASSWD_PATHãåå¨âå®è£/æ´æ°âéå¯ç¨ BasicAuthã"
    return 1
  fi
  prompt user "æ° BasicAuth ç¨æ·å" "emby"
  pass="$(random_pass)"
  prompt pass "æ° BasicAuth å¯ç ï¼çç©ºå°èªå¨çæï¼" "$pass"
  htpasswd -bc "$HTPASSWD_PATH" "$user" "$pass" >/dev/null
  reload_nginx
  echo "â å·²æ´æ° BasicAuthï¼$user / $pass"
}

action_uninstall() {
  local DOMAIN
  prompt DOMAIN "è¦å¸è½½çå¥å£ååï¼ä¾å¦ emby.bear4f.deï¼"
  DOMAIN="$(strip_scheme "$DOMAIN")"
  local conf enabled
  conf="$(conf_path_for_domain "$DOMAIN")"
  enabled="$(enabled_path_for_domain "$DOMAIN")"

  echo "å°å é¤ï¼"
  echo "  - $conf"
  echo "  - $enabled"
  echo "  - /etc/nginx/snippets/emby-gw-locations.conf"
  echo "  - $MAP_CONF"
  echo "  - $HTPASSWD_PATHï¼å¦å­å¨ï¼"
  echo

  yesno OK "ç¡®è®¤æ§è¡ï¼ä¸å¯éï¼" "n"
  [[ "$OK" == "y" ]] || { echo "å·²åæ¶"; return 0; }

  ensure_deps
  local backup dump
  backup="$(backup_nginx)"
  dump="$(mktemp)"
  trap 'rm -f "$dump"' RETURN

  rm -f "$enabled" "$conf" "$MAP_CONF" "$HTPASSWD_PATH" /etc/nginx/snippets/emby-gw-locations.conf 2>/dev/null || true

  apply_with_rollback "$backup" "$dump" || true
  echo "â å·²å¸è½½ï¼ä¸å¸è½½ nginx/certbotï¼ãå¤ä»½ç®å½ï¼$backup"
  echo "è¯ä¹¦å¦éå é¤è¯·æå¨æ§è¡ï¼certbot delete --cert-name $DOMAIN"
}

menu() {
  IFS="|" read -r OS_NAME OS_VER OS_CODE < <(os_info)
  echo "=== ${TOOL_NAME}ï¼éç¨åä»£ç½å³ï¼==="
  echo "ç³»ç»è¯å«ï¼${OS_NAME} / ${OS_VER} / ${OS_CODE}"
  echo "ç¨éï¼è®© Emby å®¢æ·ç«¯ç´æ¥å¡« https://ä½ çåå/æºç«:ç«¯å£ æ¥è§çï¼èµ°ä½  VPS æµéï¼ã"
  echo "å®å¨ï¼å¡å¿å¼å¯ BasicAuth æ IP ç½ååã"
  echo

  while true; do
    echo "========== èå =========="
    echo "1) å®è£/æ´æ° éç¨åä»£ç½å³"
    echo "2) æ¥çç¶æ"
    echo "3) ä¿®æ¹ BasicAuth è´¦å·/å¯ç "
    echo "4) å¸è½½"
    echo "0) éåº"
    echo "=========================="
    read -r -p "è¯·éæ©: " c
    case "$c" in
      1) action_install_or_update ;;
      2) action_status ;;
      3) action_change_auth ;;
      4) action_uninstall ;;
      0) exit 0 ;;
      *) echo "æ æéé¡¹" ;;
    esac
  done
}

need_root
menu

