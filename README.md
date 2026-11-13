# Nginx Basic Auth Generator

Manage an `.htpasswd` file for Nginx (or Apache) basic auth — add, remove, list and verify users from one script, with safe password handling and atomic writes.

## Features

- **bcrypt first** — hashes with bcrypt when OpenSSL supports it, apr1 fallback.
- **Passwords never in argv** — prompted interactively (no `ps`/history leaks); `--password` exists only for scripts.
- **Atomic writes** — temp file + `mv`, `640` permissions, timestamped `.bak` backup on every change.
- **Verify** — `check` command validates a password (via `htpasswd -vb` when present, else OpenSSL re-hash).
- **Nginx snippet** — `snippet` prints the exact `auth_basic` block to paste into your `server { }`.

## Usage

```bash
# Add a user (prompts for the password twice):
./htpasswd-manage.sh --file /etc/nginx/.htpasswd add alice

# Update a password, remove a user, list users:
./htpasswd-manage.sh --file /etc/nginx/.htpasswd add alice
./htpasswd-manage.sh --file /etc/nginx/.htpasswd remove bob
./htpasswd-manage.sh --file /etc/nginx/.htpasswd list

# Check a password works:
./htpasswd-manage.sh --file /etc/nginx/.htpasswd check alice

# Print the Nginx config to paste:
./htpasswd-manage.sh --file /etc/nginx/.htpasswd snippet --realm "Members Only"
```

Then in Nginx:

```nginx
location / {
    auth_basic           "Members Only";
    auth_basic_user_file /etc/nginx/.htpasswd;
}
```

Reload after changes: `nginx -t && systemctl reload nginx`.

## Notes

- Usernames allow letters, digits, `.`, `_`, `-` only (a `:` would break the file format).
- bcrypt cost defaults to 10; raise with `--cost 12` on fast hardware.
- Keep the `.htpasswd` file **outside** your web root so it can never be downloaded.

## License

MIT — see [LICENSE](LICENSE).
