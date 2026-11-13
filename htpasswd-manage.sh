#!/usr/bin/env bash
# htpasswd-manage.sh — manage an Nginx/Apache .htpasswd file safely.
#
#   ./htpasswd-manage.sh --file /etc/nginx/.htpasswd add alice
#   ./htpasswd-manage.sh --file /etc/nginx/.htpasswd remove alice
#   ./htpasswd-manage.sh --file /etc/nginx/.htpasswd list
#   ./htpasswd-manage.sh --file /etc/nginx/.htpasswd snippet --realm "Members"
#
# Passwords are read from the terminal (never from argv, so they never show
# up in ps/history), hashed with bcrypt when openssl supports it, apr1
# otherwise. Writes are atomic (temp file + mv) and the file is kept at
# 640 with a timestamped backup on every change.
set -euo pipefail

PROG="$(basename "$0")"
HTPASSWD=""
ACTION=""
USERNAME=""
PASSWORD=""
REALM="Restricted"
BCRYPT_COST=10

usage() {
    cat <<EOF
Usage: $PROG --file FILE <command> [options]

Commands:
  add USERNAME [--password PASS]   Add a user (or update the password)
  remove USERNAME                  Remove a user
  list                             List users in the file
  check USERNAME                   Verify a user's password
  snippet [--realm TEXT]           Print the Nginx location snippet

Options:
  --file FILE        Path to the .htpasswd file (required)
  --password PASS    Password (avoids the prompt; prefer the prompt)
  --realm TEXT       Realm shown in the login dialog (default: Restricted)
  --cost N           bcrypt cost, 4-31 (default: 10)
  -h, --help         Show this help
EOF
    exit "${1:-0}"
}

err() { echo "$PROG: $*" >&2; }

[ $# -ge 1 ] || usage 1

# Parse --file first, wherever it appears.
ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --file)     HTPASSWD="$2"; shift 2 ;;
        --password) PASSWORD="$2"; shift 2 ;;
        --realm)    REALM="$2"; shift 2 ;;
        --cost)     BCRYPT_COST="$2"; shift 2 ;;
        -h|--help)  usage 0 ;;
        *)          ARGS+=( "$1" ); shift ;;
    esac
done

[ -n "$HTPASSWD" ] || { err "--file is required"; usage 1; }
ACTION="${ARGS[0]:-}"
[ -n "$ACTION" ] || { err "a command is required (add|remove|list|check|snippet)"; usage 1; }
USERNAME="${ARGS[1]:-}"

case "$ACTION" in
    add|remove|check)
        [ -n "$USERNAME" ] || { err "$ACTION needs a USERNAME"; exit 1; }
        [[ "$USERNAME" =~ ^[A-Za-z0-9._-]+$ ]] || { err "invalid username: $USERNAME"; exit 1; }
        [[ "$USERNAME" != *:* ]] || { err "username must not contain ':'"; exit 1; }
        ;;
esac

command -v openssl >/dev/null 2>&1 || { err "openssl is required"; exit 1; }

# bcrypt if the local openssl supports it, apr1 otherwise.
hash_password() {
    local pass="$1"
    if openssl passwd -help 2>&1 | grep -qw -- '-bcrypt'; then
        openssl passwd -bcrypt -cost "$BCRYPT_COST" -stdin <<<"$pass"
    elif openssl passwd -help 2>&1 | grep -qw -- '-apr1'; then
        openssl passwd -apr1 -stdin <<<"$pass"
    else
        err "openssl on this system supports neither -bcrypt nor -apr1"
        exit 1
    fi
}

prompt_password() {
    local p1 p2
    read -r -s -p "Password: " p1; echo
    read -r -s -p "Password (again): " p2; echo
    [ "$p1" = "$p2" ] || { err "passwords do not match"; exit 1; }
    [ -n "$p1" ] || { err "empty password not allowed"; exit 1; }
    printf '%s' "$p1"
}

backup() {
    if [ -f "$HTPASSWD" ]; then
        cp -p "$HTPASSWD" "${HTPASSWD}.bak.$(date +%Y%m%d%H%M%S)"
    fi
}

case "$ACTION" in
    add)
        if [ -z "$PASSWORD" ]; then
            PASSWORD="$(prompt_password)"
        fi
        HASH="$(hash_password "$PASSWORD")"
        backup
        TMP="$(mktemp "$(dirname "$HTPASSWD")/.htpasswd.XXXXXX")"
        trap 'rm -f "$TMP"' EXIT
        if [ -f "$HTPASSWD" ]; then
            grep -v "^${USERNAME}:" "$HTPASSWD" > "$TMP" || true
        fi
        printf '%s:%s\n' "$USERNAME" "$HASH" >> "$TMP"
        chmod 640 "$TMP"
        mv "$TMP" "$HTPASSWD"
        trap - EXIT
        echo "user '${USERNAME}' added/updated in ${HTPASSWD}"
        ;;
    remove)
        [ -f "$HTPASSWD" ] || { err "file not found: $HTPASSWD"; exit 1; }
        grep -q "^${USERNAME}:" "$HTPASSWD" || { err "user '${USERNAME}' not found"; exit 1; }
        backup
        TMP="$(mktemp "$(dirname "$HTPASSWD")/.htpasswd.XXXXXX")"
        trap 'rm -f "$TMP"' EXIT
        grep -v "^${USERNAME}:" "$HTPASSWD" > "$TMP"
        chmod 640 "$TMP"
        mv "$TMP" "$HTPASSWD"
        trap - EXIT
        echo "user '${USERNAME}' removed from ${HTPASSWD}"
        ;;
    list)
        if [ ! -f "$HTPASSWD" ]; then
            echo "(no users — file does not exist yet: $HTPASSWD)"
            exit 0
        fi
        cut -d: -f1 "$HTPASSWD"
        ;;
    check)
        [ -f "$HTPASSWD" ] || { err "file not found: $HTPASSWD"; exit 1; }
        STORED="$(grep "^${USERNAME}:" "$HTPASSWD" | cut -d: -f2- || true)"
        [ -n "$STORED" ] || { err "user '${USERNAME}' not found"; exit 1; }
        if [ -z "$PASSWORD" ]; then
            read -r -s -p "Password: " PASSWORD; echo
        fi
        # htpasswd -vb when available, else openssl verify for apr1/bcrypt.
        if command -v htpasswd >/dev/null 2>&1; then
            if htpasswd -vb "$HTPASSWD" "$USERNAME" "$PASSWORD" >/dev/null 2>&1; then
                echo "password correct for '${USERNAME}'"
            else
                echo "password WRONG for '${USERNAME}'"
                exit 1
            fi
        else
            SALT="$(printf '%s' "$STORED" | cut -d'$' -f3)"
            ALG="$(printf '%s' "$STORED" | cut -d'$' -f2)"
            case "$ALG" in
                apr1) CAND="$(openssl passwd -apr1 -salt "$SALT" -stdin <<<"$PASSWORD")" ;;
                2y|2b|2a) CAND="$(openssl passwd -bcrypt -salt "$SALT" -stdin <<<"$PASSWORD" 2>/dev/null || true)" ;;
                *) err "unsupported hash type in file: $ALG"; exit 1 ;;
            esac
            if [ "$CAND" = "$STORED" ]; then
                echo "password correct for '${USERNAME}'"
            else
                echo "password WRONG for '${USERNAME}'"
                exit 1
            fi
        fi
        ;;
    snippet)
        cat <<EOF
# Add inside your server { } block (Nginx):
location / {
    auth_basic           "${REALM}";
    auth_basic_user_file ${HTPASSWD};
    # ... your existing directives ...
}
# Then test + reload: nginx -t && systemctl reload nginx
EOF
        ;;
    *)
        err "unknown command: $ACTION"
        usage 1
        ;;
esac
