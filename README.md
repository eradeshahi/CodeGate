# CodeGate

A self-hosted [Model Context Protocol](https://modelcontextprotocol.io) server that lets an MCP client read, search and edit code on your machine and run allowlisted dev commands — limited to the directories and permissions you configure, behind OAuth 2.1 login.

## Features

**File tools**
- `list_directory_tree`, `find_files_by_glob`, `find_files_by_name_keyword`
- `search_in_files_by_text` — literal or regex, case-insensitive option, context lines
- `get_file_text_by_path` — line ranges (`offset` / `limit`) and optional line numbers
- `create_new_file`, `replace_text_in_file`, `multi_edit` (all-or-nothing), `move_file`
- `file_info` — size, line count, line-ending style, BOM

Edits require a unique match (or `replace_all=true`), return a unified diff, are written atomically and keep the file's original line endings (LF/CRLF) and UTF-8 BOM.
Heavy folders (`node_modules`, `vendor`, `.git`, `dist`, …) are skipped when searching.

**Git (read-only)** — `git_status`, `git_diff`, `git_log`

**Commands** — `run_command` runs allowlisted executables (e.g. `php artisan test`, `npm test`) with `shell=False`, a timeout and output limits.

**Security**
- Per-directory permissions: `read`, `write`, `execute` or `full`; the most specific path wins
- Path traversal protection; secrets (`.env`, `*.pem`, `*.key`, `id_rsa*`, `.git/config`, …) are always denied
- OAuth 2.1 authorization code flow with mandatory S256 PKCE, redirect-URI allowlist, login rate limiting
- Short-lived access tokens + rotating refresh tokens; only token hashes are stored on disk
- Inline-code flags (`python -c`, `node -e`, `php -r`) and destructive commands are blocked
- Optional DNS-rebinding protection

## Requirements

- Python 3.11+
- `pip install -r requirements.txt`

## Setup

1. Copy the example config:

   ```bash
   cp config.example.json config.json
   ```

2. Generate a password hash and paste the output into the `oauth` section:

   ```bash
   python secure_files_mcp.py --hash-password
   ```

3. Edit `config.json`: set `oauth.username`, a random `oauth.client_id`, your `directories`, and `server.public_url` if the server is exposed through a tunnel or reverse proxy.

4. Run:

   ```bash
   python secure_files_mcp.py --config config.json
   ```

   Options: `--host`, `--port`, `--internal-port`, `--transport {sse,streamable-http,stdio}`.

5. Add the server to your MCP client using `https://<your-domain>/mcp` (streamable-http) or `/sse`. The client opens the login page, then receives a token automatically.

## Configuration

| Key | Description |
| --- | --- |
| `server.host` / `port` | Listen address (default `127.0.0.1:64346`) |
| `server.transport` | `streamable-http`, `sse` or `stdio` |
| `server.public_url` | Public base URL used in OAuth metadata |
| `server.allow_query_token` | Accept `?access_token=` (default `false`) |
| `oauth.access_token_ttl_seconds` | Access token lifetime (default `3600`) |
| `oauth.refresh_token_ttl_seconds` | Refresh token lifetime (default 30 days) |
| `oauth.allowed_redirect_uris` | Allowed OAuth callback URLs of your MCP client (required); loopback URLs are always allowed |
| `oauth.token_store_path` | Token hash file, relative to the config (default `tokens.json`) |
| `directories[]` | `{ "path": "...", "permissions": ["read"] }` |
| `create_allowed_dirs` | Create missing configured directories at startup |
| `security.block_hidden_files` | Hide dot-files (default `true`) |
| `security.denied_files` | Glob patterns that can never be accessed |
| `limits.max_read_bytes` | Max file size to read (`0` = unlimited) |
| `limits.max_list_items` | Max results for listings/searches |
| `limits.ignored_dirs` | Folder names skipped when walking |
| `commands.allowlist` | Allowed executables or command prefixes |
| `commands.blocked_commands` / `blocked_patterns` / `blocked_args` | Deny rules for `run_command` |
| `commands.timeout_seconds` / `max_output_chars` | Command limits |

## Security notes

- Never commit `config.json` or `tokens.json` (both are in `.gitignore`).
- An allowlisted interpreter (`python`, `node`, `php`) can still run any script file inside an `execute` directory, and `npx`/`pip` can download packages. Only grant `execute` where you accept that.
- Expose the server only over HTTPS.

## License

MIT
