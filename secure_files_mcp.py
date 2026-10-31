import argparse
import base64
import difflib
import fnmatch
import hashlib
import hmac
import html
import json
import logging
import os
import re
import secrets
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qs, urlencode, urlparse

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

from mcp.server.fastmcp import FastMCP

try:
    from starlette.requests import Request
    from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
    from starlette.routing import Route
    from starlette.applications import Starlette
    import uvicorn
    HAS_STARLETTE = True
except ImportError:
    HAS_STARLETTE = False

try:
    from mcp.server.transport_security import TransportSecuritySettings
except Exception:
    TransportSecuritySettings = None

DEFAULT_CONFIG = "config.json"
DEFAULT_SERVER_HOST = "127.0.0.1"
DEFAULT_SERVER_PORT = 64346
DEFAULT_TRANSPORT = "sse"
CONFIG: Dict[str, Any] = {}
ALLOWED_ROOTS: List[Path] = []
DIRECTORY_RULES: List[Dict[str, Any]] = []
PROJECT_ROOT: Optional[Path] = None
mcp: Optional[FastMCP] = None

_TOKEN_STORE: Dict[str, Dict[str, Any]] = {}
_CODE_STORE:  Dict[str, Dict]  = {}
_LOGIN_FAILURES: Dict[str, List[float]] = {}
TOKEN_STORE_PATH: Optional[Path] = None
DEFAULT_TOKEN_TTL = 3600
DEFAULT_REFRESH_TTL = 30 * 24 * 3600
CODE_TTL = 120
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 15 * 60
DEFAULT_REDIRECT_URIS: List[str] = []
DEFAULT_DENIED_FILES = [
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*", "id_ed25519*",
    ".git/config", ".git-credentials", ".npmrc", ".pypirc", "auth.json",
]
DEFAULT_BLOCKED_ARGS = {
    "python": ["-c"], "python3": ["-c"], "py": ["-c"],
    "node": ["-e", "--eval", "-p", "--print"],
    "php": ["-r", "-a"],
}
VALID_PERMISSIONS = {"read", "write", "execute"}


def _server_cfg() -> Dict[str, Any]:
    return CONFIG.get("server", {})

def _server_host() -> str:
    return str(_server_cfg().get("host", DEFAULT_SERVER_HOST))

def _server_port() -> int:
    return int(_server_cfg().get("port", DEFAULT_SERVER_PORT))

def _public_host(host: str) -> str:
    return "127.0.0.1" if host in {"0.0.0.0", "::", ""} else host

def _public_base_url() -> str:
    configured = str(_server_cfg().get("public_url", "")).strip()
    if configured:
        return configured.rstrip("/")
    return f"http://{_public_host(_server_host())}:{_server_port()}"

def _configured_transport() -> str:
    return str(_server_cfg().get("transport", DEFAULT_TRANSPORT))

def _public_transport_url(transport: Optional[str] = None) -> str:
    transport = transport or _configured_transport()
    base = _public_base_url()
    if transport == "streamable-http":
        configured = str(_server_cfg().get("public_mcp_url", "")).strip()
        return configured.rstrip("/") if configured else f"{base}/mcp"
    return f"{base}/sse"

def _local_transport_url(host: str, port: int, transport: str) -> str:
    path = "/mcp" if transport == "streamable-http" else "/sse"
    return f"http://{host}:{port}{path}"

def _fallback_internal_port(host_port: int) -> int:
    configured = _server_cfg().get("internal_port")
    return int(configured) if configured is not None else host_port + 1

def _protected_resource_metadata(resource_url: str) -> Dict[str, Any]:
    base = _public_base_url()
    metadata: Dict[str, Any] = {
        "resource": resource_url,
        "authorization_servers": [base],
        "bearer_methods_supported": ["header", "query"],
    }
    if resource_url.endswith("/mcp"):
        metadata["resource_documentation"] = f"{base}/.well-known/oauth-protected-resource/mcp"
    elif resource_url.endswith("/sse"):
        metadata["resource_documentation"] = f"{base}/.well-known/oauth-protected-resource/sse"
    return metadata

def _hash_pw(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000).hex()

def _verify_user(username: str, password: str) -> bool:
    a = CONFIG.get("oauth", {})
    if username != a.get("username"):
        return False
    return hmac.compare_digest(_hash_pw(password, a.get("password_salt", "")),
                               a.get("password_hash", ""))

def _verify_client(client_id: str) -> bool:
    return hmac.compare_digest(client_id, CONFIG.get("oauth", {}).get("client_id", ""))

def _verify_pkce(verifier: str, challenge: str, method: str) -> bool:
    if method != "S256":
        return False
    digest = hashlib.sha256(verifier.encode()).digest()
    return hmac.compare_digest(base64.urlsafe_b64encode(digest).rstrip(b"=").decode(), challenge)

def _allowed_redirect_uris() -> List[str]:
    configured = CONFIG.get("oauth", {}).get("allowed_redirect_uris")
    return [str(u) for u in configured] if isinstance(configured, list) else DEFAULT_REDIRECT_URIS

def _redirect_allowed(uri: str) -> bool:
    if not uri:
        return False
    if uri in _allowed_redirect_uris():
        return True
    parsed = urlparse(uri)
    return parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}

def _client_ip(request: Request) -> str:
    fwd = request.headers.get("cf-connecting-ip") or request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def _login_locked(ip: str) -> bool:
    now = time.time()
    recent = [t for t in _LOGIN_FAILURES.get(ip, []) if now - t < LOGIN_WINDOW_SECONDS]
    _LOGIN_FAILURES[ip] = recent
    return len(recent) >= LOGIN_MAX_FAILURES

def token_ttl() -> int:
    value = CONFIG.get("oauth", {}).get("access_token_ttl_seconds", DEFAULT_TOKEN_TTL)
    try:
        ttl = int(value)
    except (TypeError, ValueError):
        raise ValueError("oauth.access_token_ttl_seconds must be an integer")
    if ttl <= 0:
        raise ValueError("oauth.access_token_ttl_seconds must be greater than zero")
    return ttl

def refresh_ttl() -> int:
    return int(CONFIG.get("oauth", {}).get("refresh_token_ttl_seconds", DEFAULT_REFRESH_TTL))

def _token_key(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def _load_tokens() -> None:
    if TOKEN_STORE_PATH is None or not TOKEN_STORE_PATH.exists():
        return
    try:
        data = json.loads(TOKEN_STORE_PATH.read_text(encoding="utf-8"))
        now = time.time()
        _TOKEN_STORE.update({k: v for k, v in data.items() if v.get("exp", 0) > now})
    except Exception as exc:
        log.warning(f"could not load token store: {exc}")

def _save_tokens() -> None:
    if TOKEN_STORE_PATH is None:
        return
    now = time.time()
    for k in [k for k, v in _TOKEN_STORE.items() if v["exp"] <= now]:
        del _TOKEN_STORE[k]
    tmp = TOKEN_STORE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(_TOKEN_STORE), encoding="utf-8")
    os.replace(tmp, TOKEN_STORE_PATH)

def _issue_token(kind: str = "access") -> str:
    t = secrets.token_urlsafe(48)
    ttl = token_ttl() if kind == "access" else refresh_ttl()
    _TOKEN_STORE[_token_key(t)] = {"exp": time.time() + ttl, "kind": kind}
    _save_tokens()
    return t

def _valid_token(token: str, kind: str = "access") -> bool:
    if not token:
        return False
    key = _token_key(token)
    entry = _TOKEN_STORE.get(key)
    if not entry or entry.get("kind") != kind:
        return False
    if time.time() > entry["exp"]:
        del _TOKEN_STORE[key]
        return False
    return True

def _token_response() -> Dict[str, Any]:
    return {"access_token": _issue_token("access"), "token_type": "Bearer",
            "expires_in": token_ttl(), "refresh_token": _issue_token("refresh"), "scope": "mcp"}


def _login_html(redirect_uri, state, client_id, code_challenge, ccm, error=""):
    err = f'<p class="err">{html.escape(error)}</p>' if error else ""
    qs  = html.escape(urlencode({"redirect_uri": redirect_uri, "state": state,
                     "client_id": client_id, "code_challenge": code_challenge,
                     "code_challenge_method": ccm}), quote=True)
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>CodeGate</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,sans-serif;background:#0f172a;display:flex;
     align-items:center;justify-content:center;min-height:100vh}}
.card{{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:2rem;width:360px}}
h1{{color:#f1f5f9;font-size:1.2rem;margin-bottom:1.5rem;text-align:center}}
label{{color:#94a3b8;font-size:.85rem;display:block;margin-bottom:.3rem}}
input{{width:100%;padding:.6rem .8rem;border-radius:6px;border:1px solid #475569;
       background:#0f172a;color:#f1f5f9;font-size:1rem;margin-bottom:1rem;outline:none}}
input:focus{{border-color:#6366f1}}
button{{width:100%;padding:.7rem;background:#6366f1;color:#fff;border:none;
        border-radius:6px;font-size:1rem;cursor:pointer}}
button:hover{{background:#4f46e5}}
.err{{color:#f87171;font-size:.85rem;margin-bottom:1rem;text-align:center}}
</style></head><body><div class="card">
<h1>🔒 CodeGate</h1>{err}
<form method="POST" action="/login?{qs}">
<label>Username</label>
<input type="text" name="username" autofocus autocomplete="username"/>
<label>Password</label>
<input type="password" name="password" autocomplete="current-password"/>
<button type="submit">Sign in</button>
</form></div></body></html>"""


async def ep_authorize(request: Request) -> Response:
    p = dict(request.query_params)
    if p.get("response_type") != "code":
        return JSONResponse({"error": "unsupported_response_type"}, status_code=400)
    err = _check_authorize_params(p)
    if err:
        return err
    return HTMLResponse(_login_html(
        p.get("redirect_uri",""), p.get("state",""), p.get("client_id",""),
        p.get("code_challenge",""), p.get("code_challenge_method","S256")))

def _check_authorize_params(p: Dict[str, str]) -> Optional[Response]:
    if not _verify_client(p.get("client_id", "")):
        return JSONResponse({"error": "invalid_client"}, status_code=400)
    if not _redirect_allowed(p.get("redirect_uri", "")):
        log.warning(f"[authorize] rejected redirect_uri={p.get('redirect_uri','')!r}")
        return JSONResponse({"error": "invalid_request",
                             "error_description": "redirect_uri not allowed"}, status_code=400)
    if not p.get("code_challenge") or p.get("code_challenge_method", "S256") != "S256":
        return JSONResponse({"error": "invalid_request",
                             "error_description": "S256 PKCE required"}, status_code=400)
    return None

async def ep_login(request: Request) -> Response:
    p    = dict(request.query_params)
    err  = _check_authorize_params(p)
    if err:
        return err
    ip   = _client_ip(request)
    if _login_locked(ip):
        log.warning(f"[login] locked out ip={ip}")
        return HTMLResponse(_login_html(
            p.get("redirect_uri",""), p.get("state",""), p.get("client_id",""),
            p.get("code_challenge",""), "S256",
            error="Too many failed attempts. Try again later."), status_code=429)
    form = await request.form()
    user = str(form.get("username",""))
    pw   = str(form.get("password",""))

    if not _verify_user(user, pw):
        _LOGIN_FAILURES.setdefault(ip, []).append(time.time())
        log.warning(f"[login] failed attempt ip={ip}")
        return HTMLResponse(_login_html(
            p.get("redirect_uri",""), p.get("state",""), p.get("client_id",""),
            p.get("code_challenge",""), p.get("code_challenge_method","S256"),
            error="Invalid username or password."), status_code=401)

    _LOGIN_FAILURES.pop(ip, None)
    now = time.time()
    for c in [c for c, e in _CODE_STORE.items() if e["expires_at"] < now]:
        del _CODE_STORE[c]
    code = secrets.token_urlsafe(32)
    _CODE_STORE[code] = {
        "expires_at": time.time() + CODE_TTL,
        "redirect_uri": p.get("redirect_uri",""),
        "client_id": p.get("client_id",""),
        "code_challenge": p.get("code_challenge",""),
        "ccm": p.get("code_challenge_method","S256"),
    }
    ru  = p.get("redirect_uri","")
    sep = "&" if "?" in ru else "?"
    return RedirectResponse(f"{ru}{sep}{urlencode({'code': code, 'state': p.get('state','')})}",
                            status_code=302)

async def ep_token(request: Request) -> Response:
    ct = request.headers.get("content-type","")
    if "application/json" in ct:
        body = await request.json()
    else:
        raw  = await request.body()
        body = {k: v[0] for k, v in parse_qs(raw.decode()).items()}

    client_id     = body.get("client_id","")
    grant_type    = body.get("grant_type","")
    code          = body.get("code","")
    code_verifier = body.get("code_verifier","")
    redirect_uri  = body.get("redirect_uri","")

    log.info(f"[token] client_id={client_id!r} grant={grant_type!r} "
             f"code={'Y' if code else 'N'} verifier={'Y' if code_verifier else 'N'}")

    if not _verify_client(client_id):
        log.warning(f"[token] invalid client_id={client_id!r}")
        return JSONResponse({"error":"invalid_client"}, status_code=401)

    if grant_type == "refresh_token":
        old = body.get("refresh_token","")
        if not _valid_token(old, "refresh"):
            return JSONResponse({"error":"invalid_grant","error_description":"bad refresh token"}, status_code=400)
        _TOKEN_STORE.pop(_token_key(old), None)
        log.info(f"[token] refreshed for client_id={client_id!r}")
        return JSONResponse(_token_response())

    if grant_type != "authorization_code":
        return JSONResponse({"error":"unsupported_grant_type"}, status_code=400)

    entry = _CODE_STORE.pop(code, None)
    if not entry:
        return JSONResponse({"error":"invalid_grant","error_description":"unknown code"}, status_code=400)
    if time.time() > entry["expires_at"]:
        return JSONResponse({"error":"invalid_grant","error_description":"code expired"}, status_code=400)
    if entry["redirect_uri"] != redirect_uri:
        return JSONResponse({"error":"invalid_grant","error_description":"redirect_uri mismatch"}, status_code=400)

    if not code_verifier:
        return JSONResponse({"error":"invalid_grant","error_description":"code_verifier required"}, status_code=400)
    if not _verify_pkce(code_verifier, entry["code_challenge"], entry.get("ccm","S256")):
        return JSONResponse({"error":"invalid_grant","error_description":"PKCE mismatch"}, status_code=400)

    log.info(f"[token] issued OK for client_id={client_id!r}")
    return JSONResponse(_token_response())

async def ep_metadata(request: Request) -> Response:
    base = _public_base_url()
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["mcp"],
        "token_endpoint_auth_methods_supported": ["none"],
    })

async def ep_openid_configuration(request: Request) -> Response:
    base = _public_base_url()
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["mcp"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["none"],
        "token_endpoint_auth_methods_supported": ["none"],
    })

async def ep_protected_resource(request: Request) -> Response:
    active_transport = _configured_transport()
    path = request.url.path.rstrip("/")
    if path.endswith("/mcp") and active_transport == "streamable-http":
        return JSONResponse(_protected_resource_metadata(_public_transport_url("streamable-http")))
    if path.endswith("/sse") and active_transport == "sse":
        return JSONResponse(_protected_resource_metadata(_public_transport_url("sse")))
    return JSONResponse(_protected_resource_metadata(_public_transport_url(active_transport)))

async def ep_health(request: Request) -> Response:
    return JSONResponse({"status":"ok"})


PUBLIC = ("/authorize", "/login", "/token", "/.well-known/", "/health")

class BearerMiddleware:
    def __init__(self, app):
        self.app = app
    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            path = scope.get("path","")
            if not any(path.startswith(p) for p in PUBLIC):
                hdrs  = dict(scope.get("headers",[]))
                auth  = hdrs.get(b"authorization", b"").decode()
                token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""

                if not token and _server_cfg().get("allow_query_token", False):
                    qs = scope.get("query_string", b"").decode()
                    for part in qs.split("&"):
                        if part.startswith("access_token="):
                            token = part[len("access_token="):]
                            break

                log.info(f"[bearer] {scope.get('method','WS')} {path} token={'Y' if token else 'N'}")
                if not _valid_token(token):
                    log.warning(f"[bearer] REJECTED {path} — invalid/missing token")
                    r = JSONResponse({"error":"unauthorized"}, status_code=401,
                                     headers={"WWW-Authenticate":'Bearer realm="mcp"'})
                    await r(scope, receive, send)
                    return
        await self.app(scope, receive, send)


def load_config(p: str) -> Dict[str, Any]:
    path = Path(p).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(path)
    cfg = json.loads(path.read_text(encoding="utf-8"))
    if not cfg.get("directories") and not cfg.get("allowed_dirs"):
        raise ValueError("directories missing")
    if not cfg.get("oauth", {}).get("password_hash"):
        raise ValueError("Run --hash-password first")

    value = cfg.get("oauth", {}).get("access_token_ttl_seconds", DEFAULT_TOKEN_TTL)
    try:
        if int(value) <= 0:
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError("oauth.access_token_ttl_seconds must be a positive integer")
    return cfg

def _normalize_permissions(raw_permissions: Any) -> Set[str]:
    if isinstance(raw_permissions, str):
        permissions = {raw_permissions.lower().strip()}
    elif isinstance(raw_permissions, list):
        permissions = {str(p).lower().strip() for p in raw_permissions}
    else:
        raise ValueError("directory permissions must be a string or list")

    if "full" in permissions:
        permissions.remove("full")
        permissions.update(VALID_PERMISSIONS)

    invalid = permissions - VALID_PERMISSIONS
    if invalid:
        raise ValueError(f"invalid directory permissions: {sorted(invalid)}")
    if not permissions:
        raise ValueError("directory permissions cannot be empty")
    return permissions

def init_roots(cfg: Dict[str, Any]) -> None:
    global ALLOWED_ROOTS, DIRECTORY_RULES, PROJECT_ROOT

    entries = cfg.get("directories")
    if not entries:
        entries = [
            {"path": raw, "permissions": ["read", "write"]}
            for raw in cfg.get("allowed_dirs", [])
        ]
        log.warning("allowed_dirs is deprecated; migrate to directories with explicit permissions")

    roots: List[Path] = []
    rules: List[Dict[str, Any]] = []
    for entry in entries:
        if isinstance(entry, str):
            raw_path = entry
            permissions = {"read", "write"}
        elif isinstance(entry, dict):
            raw_path = entry.get("path")
            permissions = _normalize_permissions(entry.get("permissions", ["read"]))
        else:
            raise ValueError("each directories entry must be an object")

        if not raw_path:
            raise ValueError("directory path missing")
        root = Path(str(raw_path)).expanduser().resolve()
        if not root.exists():
            if cfg.get("create_allowed_dirs"):
                root.mkdir(parents=True, exist_ok=True)
            else:
                raise FileNotFoundError(root)
        if not root.is_dir():
            raise NotADirectoryError(root)

        roots.append(root)
        rules.append({"path": root, "permissions": set(permissions)})

    if not roots:
        raise ValueError("at least one directory must be configured")

    DIRECTORY_RULES = sorted(rules, key=lambda rule: len(rule["path"].parts), reverse=True)
    ALLOWED_ROOTS = roots
    PROJECT_ROOT = roots[0]

def _rule_for_path(path: Path) -> Optional[Dict[str, Any]]:
    for rule in DIRECTORY_RULES:
        try:
            path.relative_to(rule["path"])
            return rule
        except ValueError:
            continue
    return None

def can_access(path: Path, required_permission: str = "read") -> bool:
    permission = required_permission.lower().strip()
    if permission not in VALID_PERMISSIONS:
        raise ValueError(f"unknown permission: {required_permission}")
    rule = _rule_for_path(path.resolve())
    return bool(rule and permission in rule["permissions"])

def safe(user_path: str, required_permission: str = "read") -> Path:
    if PROJECT_ROOT is None:
        raise RuntimeError("directory roots are not initialized")
    raw = Path(user_path).expanduser()
    if not raw.is_absolute():
        raw = PROJECT_ROOT / raw
    resolved = raw.resolve()
    if is_denied_file(resolved):
        raise PermissionError(f"Access denied (sensitive file): {user_path}")
    rule = _rule_for_path(resolved)
    if not rule:
        raise PermissionError(f"Access denied: {user_path}")
    if required_permission not in rule["permissions"]:
        raise PermissionError(
            f"{required_permission} access denied: {user_path} "
            f"(configured permissions: {sorted(rule['permissions'])})"
        )
    return resolved

def _denied_file_patterns() -> List[str]:
    value = CONFIG.get("security", {}).get("denied_files", DEFAULT_DENIED_FILES)
    return [str(x).lower() for x in value] if isinstance(value, list) else DEFAULT_DENIED_FILES

def is_denied_file(path: Path) -> bool:
    name = path.name.lower()
    posix = path.as_posix().lower()
    for pattern in _denied_file_patterns():
        if "/" in pattern:
            if posix.endswith("/" + pattern) or fnmatch.fnmatch(posix, "*/" + pattern):
                return True
        elif fnmatch.fnmatch(name, pattern):
            return True
    return False

def skip(path: Path) -> bool:
    if is_denied_file(path):
        return True
    if CONFIG.get("security",{}).get("block_hidden_files", True):
        return any(p.startswith(".") for p in path.parts)
    return False

def max_bytes() -> Optional[int]:
    value = CONFIG.get("limits", {}).get("max_read_bytes", 1_000_000)
    if value in (None, 0, "0"):
        return None
    limit = int(value)
    if limit < 0:
        raise ValueError("limits.max_read_bytes cannot be negative")
    return limit
def max_items() -> int:  return int(CONFIG.get("limits",{}).get("max_list_items", 1000))


def _commands_cfg() -> Dict[str, Any]:
    return CONFIG.get("commands", {})


def _command_timeout_seconds() -> int:
    value = _commands_cfg().get("timeout_seconds", 120)
    try:
        timeout = int(value)
    except (TypeError, ValueError):
        raise ValueError("commands.timeout_seconds must be an integer")
    if timeout <= 0:
        raise ValueError("commands.timeout_seconds must be greater than zero")
    return timeout


def _command_max_output_chars() -> int:
    value = _commands_cfg().get("max_output_chars", 20000)
    try:
        limit = int(value)
    except (TypeError, ValueError):
        raise ValueError("commands.max_output_chars must be an integer")
    if limit <= 0:
        raise ValueError("commands.max_output_chars must be greater than zero")
    return limit


def _split_config_command(value: str) -> List[str]:
    return shlex.split(str(value), posix=(os.name != "nt"))


def _normalize_command_part(value: str) -> str:
    return str(value).strip().replace("\\", "/").lower()


def _is_delete_or_dangerous_command(parts: List[str]) -> bool:
    if not parts:
        return True

    executable = _normalize_command_part(parts[0])
    executable_name = Path(executable).name.lower()

    blocked_commands = {
        _normalize_command_part(x)
        for x in _commands_cfg().get("blocked_commands", [
            "rm", "rmdir", "del", "erase", "rd", "remove-item",
            "unlink", "shred", "trash", "move-item"
        ])
    }

    if executable in blocked_commands or executable_name in blocked_commands:
        return True

    blocked_args = _commands_cfg().get("blocked_args", DEFAULT_BLOCKED_ARGS)
    stem = executable_name.rsplit(".", 1)[0] if executable_name.endswith((".exe", ".cmd", ".bat")) else executable_name
    flags = {str(f).lower() for f in blocked_args.get(stem, [])}
    for arg in parts[1:]:
        a = _normalize_command_part(arg)
        if a in flags or any(a.startswith(f + "=") for f in flags if f.startswith("--")):
            return True

    command_line = " ".join(_normalize_command_part(p) for p in parts)
    blocked_patterns = [
        str(x).lower()
        for x in _commands_cfg().get("blocked_patterns", [
            "rm -rf", "rm -fr", "rmdir /s", "del /f", "del /s",
            "remove-item", "unlink(", "fs.unlink", "fs.rm", "fs.rmdir",
            "shutil.rmtree", "pathlib.path.unlink", "os.remove", "os.unlink",
            "os.rmdir"
        ])
    ]
    return any(pattern in command_line for pattern in blocked_patterns)


def _is_command_allowed(parts: List[str]) -> bool:
    if not parts:
        return False

    allowlist = _commands_cfg().get("allowlist", [])
    if not isinstance(allowlist, list) or not allowlist:
        return False

    normalized_parts = [_normalize_command_part(p) for p in parts]
    executable = normalized_parts[0]
    executable_name = Path(executable).name.lower()

    for raw_entry in allowlist:
        try:
            entry_parts = [_normalize_command_part(p) for p in _split_config_command(str(raw_entry))]
        except ValueError:
            continue
        if not entry_parts:
            continue

        if len(entry_parts) == 1:
            allowed = entry_parts[0]
            allowed_name = Path(allowed).name.lower()
            if executable == allowed or executable_name == allowed_name:
                return True
            continue

        if normalized_parts[:len(entry_parts)] == entry_parts:
            return True

    return False


DEFAULT_IGNORED_DIRS = [
    "node_modules", "vendor", ".git", "__pycache__", ".venv", "venv",
    ".idea", ".vscode", "dist", "build", ".next", ".nuxt", "coverage", ".cache",
]
UTF8_BOM = b"\xef\xbb\xbf"
DEFAULT_READ_LINES = 2000
MAX_DIFF_CHARS = 6000


def _ignored_dirs() -> Set[str]:
    value = CONFIG.get("limits", {}).get("ignored_dirs", DEFAULT_IGNORED_DIRS)
    return {str(x).lower() for x in value} if isinstance(value, list) else set(DEFAULT_IGNORED_DIRS)


def _walk_files(base: Path, include_dirs: bool = False):
    ignored = _ignored_dirs()
    for root, dirs, files in os.walk(base):
        rp = Path(root)
        dirs[:] = sorted(d for d in dirs
                         if d.lower() not in ignored and not skip(rp / d) and can_access(rp / d, "read"))
        if include_dirs:
            for d in dirs:
                yield rp / d
        for f in sorted(files):
            fp = rp / f
            if not skip(fp) and can_access(fp, "read"):
                yield fp


def _read_doc(p: Path) -> Dict[str, Any]:
    data = p.read_bytes()
    bom = data.startswith(UTF8_BOM)
    if bom:
        data = data[len(UTF8_BOM):]
    if b"\x00" in data[:8000]:
        raise ValueError(f"binary file: {p}")
    text = data.decode("utf-8", errors="replace")
    newline = "\r\n" if "\r\n" in text else "\n"
    return {"text": text.replace("\r\n", "\n"), "newline": newline, "bom": bom}


def _write_atomic(p: Path, data: bytes) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f".{p.name}.{secrets.token_hex(4)}.tmp")
    try:
        tmp.write_bytes(data)
        os.replace(tmp, p)
    finally:
        if tmp.exists():
            tmp.unlink()


def _write_doc(p: Path, text: str, newline: str = "\n", bom: bool = False) -> None:
    body = text.replace("\r\n", "\n").replace("\n", newline).encode("utf-8")
    _write_atomic(p, (UTF8_BOM if bom else b"") + body)


def _diff(path: Path, before: str, after: str) -> str:
    d = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                     fromfile=str(path), tofile=str(path), n=2))
    return d if len(d) <= MAX_DIFF_CHARS else d[:MAX_DIFF_CHARS] + "\n… [diff truncated]"


def _clip(s: str, limit: int) -> str:
    if len(s) <= limit:
        return s
    head = limit // 4
    tail = limit - head
    return f"{s[:head]}\n… [{len(s) - limit} chars truncated] …\n{s[-tail:]}"


def _apply_edit(text: str, old: str, new: str, replace_all: bool) -> tuple:
    old = old.replace("\r\n", "\n")
    new = new.replace("\r\n", "\n")
    if not old:
        raise ValueError("old_text must not be empty")
    n = text.count(old)
    if n == 0:
        raise ValueError("old_text not found (it must match the file exactly, including indentation)")
    if n > 1 and not replace_all:
        raise ValueError(f"old_text occurs {n} times; add surrounding lines to make it unique "
                         f"or pass replace_all=true")
    return (text.replace(old, new) if replace_all else text.replace(old, new, 1)), (n if replace_all else 1)


def _run_git(repo: Path, args: List[str], limit: int = 20000) -> str:
    cmd = ["git", "-c", "core.fsmonitor=false", "-c", "core.pager=cat",
           "-c", "diff.external=", "--no-pager", "-C", str(repo)] + args
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=60, shell=False)
    out = r.stdout if r.returncode == 0 else (r.stderr or r.stdout)
    return _clip(out, limit) or "(no output)"


def register_tools(server: FastMCP) -> None:
    @server.tool()
    def allowed_directories() -> List[Dict[str, Any]]:
        """Return configured directories and their effective permissions."""
        return [
            {"path": str(rule["path"]), "permissions": sorted(rule["permissions"])}
            for rule in DIRECTORY_RULES
        ]

    @server.tool()
    def directory_permissions(path: str = ".") -> Dict[str, Any]:
        """Return the effective permission rule for a path."""
        p = safe(path, "read")
        rule = _rule_for_path(p)
        return {"path": str(p), "root": str(rule["path"]), "permissions": sorted(rule["permissions"])}

    @server.tool()
    def list_directory_tree(path: str = ".", max_depth: int = 3) -> str:
        """Tree view of a directory. Heavy folders (node_modules, vendor, .git, ...) are skipped."""
        base = safe(path, "read")
        if not base.is_dir(): raise NotADirectoryError(str(base))
        depth = max(0, min(int(max_depth), 10))
        ignored = _ignored_dirs()
        limit, count, lines = max_items(), 0, [str(base)]
        def walk(d: Path, prefix: str, dep: int):
            nonlocal count
            if dep >= depth or count >= limit: return
            try: children = sorted(d.iterdir(), key=lambda p:(not p.is_dir(), p.name.lower()))
            except PermissionError: lines.append(prefix+"└── [denied]"); return
            children = [c for c in children if not skip(c) and can_access(c, "read")]
            for i, c in enumerate(children):
                if count >= limit: lines.append(prefix+"└── [truncated]"); return
                count += 1
                last = i == len(children)-1
                conn = "└── " if last else "├── "
                is_ignored = c.is_dir() and c.name.lower() in ignored
                lines.append(prefix+conn+c.name+("/" if c.is_dir() else "")+(" [skipped]" if is_ignored else ""))
                if c.is_dir() and not is_ignored:
                    walk(c, prefix+("    " if last else "│   "), dep+1)
        walk(base, "", 0)
        return "\n".join(lines)

    @server.tool()
    def find_files_by_glob(pattern: str, base_dir: str = ".") -> List[str]:
        """Find files by glob pattern relative to base_dir, e.g. **/*.py or app/**/*Controller.php.
        Ignored folders (node_modules, vendor, .git, ...) are not searched."""
        base = safe(base_dir, "read")
        res, lim = [], max_items()
        for item in _walk_files(base):
            if len(res) >= lim: break
            rel = item.relative_to(base).as_posix()
            if fnmatch.fnmatch(rel, pattern) or (pattern.startswith("**/") and fnmatch.fnmatch(rel, pattern[3:])):
                res.append(str(item))
        return res

    @server.tool()
    def find_files_by_name_keyword(keyword: str, base_dir: str = ".") -> List[str]:
        """Find files and folders whose names contain keyword (case-insensitive)."""
        base = safe(base_dir, "read"); kw = keyword.lower(); res, lim = [], max_items()
        for item in _walk_files(base, include_dirs=True):
            if len(res) >= lim: break
            if kw in item.name.lower(): res.append(str(item))
        return res

    @server.tool()
    def search_in_files_by_text(
        text: str,
        base_dir: str = ".",
        glob_pattern: str = "**/*",
        regex: bool = False,
        case_sensitive: bool = True,
        context_lines: int = 0,
        max_results: int = 200,
    ) -> List[Dict[str, Any]]:
        """Search file contents and return every matching line.

        - text: literal string, or a Python regular expression when regex=true.
        - glob_pattern: limit to files, e.g. "**/*.php".
        - context_lines: lines of context before/after each match (0-5).
        Returns [{path, line, text, context?}]. Ignored folders are skipped."""
        base = safe(base_dir, "read")
        flags = 0 if case_sensitive else re.IGNORECASE
        rx = re.compile(text if regex else re.escape(text), flags)
        ctx = max(0, min(int(context_lines), 5))
        cap = max(1, min(int(max_results), max_items()))
        limit = max_bytes() or 5_000_000
        res: List[Dict[str, Any]] = []
        for item in _walk_files(base):
            rel = item.relative_to(base).as_posix()
            if not (fnmatch.fnmatch(rel, glob_pattern) or
                    (glob_pattern.startswith("**/") and fnmatch.fnmatch(rel, glob_pattern[3:]))):
                continue
            try:
                if item.stat().st_size > limit: continue
                lines = _read_doc(item)["text"].split("\n")
            except Exception:
                continue
            for i, line in enumerate(lines):
                if rx.search(line):
                    hit: Dict[str, Any] = {"path": str(item), "line": i + 1, "text": line[:500]}
                    if ctx:
                        lo, hi = max(0, i - ctx), min(len(lines), i + ctx + 1)
                        hit["context"] = "\n".join(f"{n+1}: {lines[n][:500]}" for n in range(lo, hi))
                    res.append(hit)
                    if len(res) >= cap:
                        return res
        return res

    @server.tool()
    def get_file_text_by_path(path: str, offset: int = 1, limit: int = 0, line_numbers: bool = False) -> str:
        """Read a text file.

        - offset: first line to return (1-based).
        - limit: number of lines (0 = up to 2000 lines; a note says if more remain).
        - line_numbers: prefix each line with its number (useful before editing).
        Line endings are returned as \\n regardless of the file's style."""
        p = safe(path, "read")
        if skip(p): raise PermissionError("hidden")
        if not p.is_file(): raise FileNotFoundError(str(p))
        lim = max_bytes()
        if lim is not None and p.stat().st_size > lim: raise ValueError("too large")
        lines = _read_doc(p)["text"].split("\n")
        start = max(1, int(offset))
        count = int(limit) if int(limit) > 0 else DEFAULT_READ_LINES
        chunk = lines[start-1:start-1+count]
        body = "\n".join(f"{start+i}\t{l}" for i, l in enumerate(chunk)) if line_numbers else "\n".join(chunk)
        remaining = len(lines) - (start - 1 + len(chunk))
        if remaining > 0:
            body += f"\n… [{remaining} more lines; continue with offset={start+len(chunk)}]"
        return body

    @server.tool()
    def create_new_file(path: str, text: str = "", overwrite: bool = False) -> str:
        """Create a text file (written atomically). With overwrite=true an existing
        file keeps its line-ending style and BOM."""
        p = safe(path, "write")
        if skip(p): raise PermissionError("hidden")
        if p.exists() and not overwrite: raise FileExistsError(str(p))
        if p.exists():
            doc = _read_doc(p)
            _write_doc(p, text, doc["newline"], doc["bom"])
        else:
            _write_atomic(p, text.encode("utf-8"))
        return f"created: {p}"

    @server.tool()
    def replace_text_in_file(path: str, old_text: str, new_text: str, replace_all: bool = False) -> str:
        """Replace an exact snippet in a file and return the resulting diff.

        old_text must match exactly (including indentation) and be unique in the
        file unless replace_all=true; otherwise an error explains what to fix.
        The file's line endings and BOM are preserved."""
        p = safe(path, "write")
        if skip(p): raise PermissionError("hidden")
        if not p.is_file(): raise FileNotFoundError(str(p))
        doc = _read_doc(p)
        updated, n = _apply_edit(doc["text"], old_text, new_text, replace_all)
        _write_doc(p, updated, doc["newline"], doc["bom"])
        return f"replaced {n} occurrence(s)\n{_diff(p, doc['text'], updated)}"

    @server.tool()
    def multi_edit(path: str, edits: List[Dict[str, Any]]) -> str:
        """Apply several replacements to one file in order, all or nothing.

        edits: [{"old_text": "...", "new_text": "...", "replace_all": false}, ...]
        Each old_text is matched against the result of the previous edits.
        If any edit fails, the file is left unchanged. Returns the combined diff."""
        p = safe(path, "write")
        if skip(p): raise PermissionError("hidden")
        if not p.is_file(): raise FileNotFoundError(str(p))
        if not edits: raise ValueError("edits must not be empty")
        doc = _read_doc(p)
        text = doc["text"]
        for i, e in enumerate(edits, 1):
            try:
                text, _ = _apply_edit(text, str(e.get("old_text", "")), str(e.get("new_text", "")),
                                      bool(e.get("replace_all", False)))
            except ValueError as exc:
                raise ValueError(f"edit {i}: {exc}; no changes were written")
        _write_doc(p, text, doc["newline"], doc["bom"])
        return f"applied {len(edits)} edit(s)\n{_diff(p, doc['text'], text)}"

    @server.tool()
    def move_file(source: str, destination: str) -> str:
        """Move or rename a file or folder. Needs write permission on both paths;
        never overwrites an existing destination."""
        src = safe(source, "write")
        dst = safe(destination, "write")
        if skip(src) or skip(dst): raise PermissionError("hidden")
        if not src.exists(): raise FileNotFoundError(str(src))
        if dst.exists(): raise FileExistsError(str(dst))
        dst.parent.mkdir(parents=True, exist_ok=True)
        os.replace(src, dst)
        return f"moved: {src} -> {dst}"

    @server.tool()
    def file_info(path: str) -> Dict[str, Any]:
        """File/directory metadata, including line count and line-ending style for text files."""
        p = safe(path, "read")
        if skip(p): raise PermissionError("hidden")
        s = p.stat()
        info = {"path":str(p),"is_file":p.is_file(),"is_dir":p.is_dir(),
                "size_bytes":s.st_size,"modified_time":s.st_mtime}
        if p.is_file() and s.st_size <= 5_000_000:
            try:
                doc = _read_doc(p)
                info.update({"lines": doc["text"].count("\n") + 1,
                             "line_endings": "CRLF" if doc["newline"] == "\r\n" else "LF",
                             "utf8_bom": doc["bom"]})
            except ValueError:
                info["binary"] = True
        return info

    @server.tool()
    def git_status(path: str = ".") -> str:
        """Short git status (branch + changed files) of the repository containing path."""
        return _run_git(safe(path, "read"), ["status", "--short", "--branch"])

    @server.tool()
    def git_diff(path: str = ".", staged: bool = False, file: str = "") -> str:
        """Unified diff of uncommitted changes. staged=true shows the index;
        file limits the diff to one path relative to the repository."""
        args = ["diff", "--no-ext-diff", "--no-textconv", "--no-color"] + (["--cached"] if staged else [])
        if file:
            safe(str(Path(path) / file) if not Path(file).is_absolute() else file, "read")
            args += ["--", file]
        return _run_git(safe(path, "read"), args, limit=_command_max_output_chars())

    @server.tool()
    def git_log(path: str = ".", max_count: int = 20) -> str:
        """Recent commits (hash, date, author, subject)."""
        n = max(1, min(int(max_count), 200))
        return _run_git(safe(path, "read"),
                        ["log", f"-n{n}", "--date=short", "--pretty=format:%h %ad %an  %s"])

    @server.tool()
    def run_command(
        command: str,
        args: Optional[List[str]] = None,
        cwd: str = ".",
        timeout_seconds: Optional[int] = None,
        max_output_chars: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Run an allowlisted development/test command inside an execute-enabled directory.

        The command executable must be present in commands.allowlist in config.json.
        The cwd must be inside a configured directory with execute permission.

        Examples:
        - command="php", args=["-v"]
        - command="php", args=["artisan", "test"]
        - command="php artisan test"
        - command="npm", args=["test"]
        - command="npm test"
        """
        workdir = safe(cwd, "execute")
        if skip(workdir):
            raise PermissionError("hidden")
        if not workdir.is_dir():
            raise NotADirectoryError(str(workdir))

        if not isinstance(command, str) or not command.strip():
            raise ValueError("command must be a non-empty string")

        if args is None:
            try:
                parts = shlex.split(command.strip(), posix=(os.name != "nt"))
            except ValueError as exc:
                raise ValueError(f"invalid command syntax: {exc}")
        elif isinstance(args, list):
            command_args = [str(arg) for arg in args]
            parts = [command.strip()] + command_args
        else:
            raise ValueError("args must be a list of strings")

        if not parts:
            raise ValueError("command cannot be empty")

        if _is_delete_or_dangerous_command(parts):
            raise PermissionError("Command is blocked because it looks destructive or dangerous")

        if not _is_command_allowed(parts):
            raise PermissionError(
                "Command is not in commands.allowlist. Add it to config.json first."
            )

        timeout = int(timeout_seconds or _command_timeout_seconds())
        output_limit = int(max_output_chars or _command_max_output_chars())
        if timeout <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        if output_limit <= 0:
            raise ValueError("max_output_chars must be greater than zero")

        try:
            result = subprocess.run(
                parts,
                cwd=str(workdir),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                shell=False,
            )
        except FileNotFoundError as exc:
            return {
                "command": parts,
                "cwd": str(workdir),
                "exit_code": 127,
                "stdout": "",
                "stderr": str(exc),
                "timed_out": False,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            return {
                "command": parts,
                "cwd": str(workdir),
                "exit_code": 124,
                "stdout": _clip(stdout, output_limit),
                "stderr": _clip(stderr, output_limit),
                "timed_out": True,
                "stdout_truncated": len(stdout) > output_limit,
                "stderr_truncated": len(stderr) > output_limit,
                "message": f"Command timed out after {timeout} seconds",
            }

        stdout = result.stdout or ""
        stderr = result.stderr or ""
        return {
            "command": parts,
            "cwd": str(workdir),
            "exit_code": result.returncode,
            "stdout": _clip(stdout, output_limit),
            "stderr": _clip(stderr, output_limit),
            "timed_out": False,
            "stdout_truncated": len(stdout) > output_limit,
            "stderr_truncated": len(stderr) > output_limit,
        }


def make_ts(cfg: Dict[str, Any]) -> Any:
    if TransportSecuritySettings is None: return None
    ts = cfg.get("transport_security",{})
    parsed_public = urlparse(_public_base_url())
    local_host = _public_host(_server_host())
    default_allowed_hosts = [f"{local_host}:*"]
    default_allowed_origins = [f"http://{local_host}:*"]
    if parsed_public.hostname:
        default_allowed_hosts.append(parsed_public.hostname)
        if parsed_public.scheme and parsed_public.netloc:
            default_allowed_origins.append(f"{parsed_public.scheme}://{parsed_public.netloc}")
    if not ts.get("enabled", False):
        return TransportSecuritySettings(enable_dns_rebinding_protection=False)
    try:
        return TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=ts.get("allowed_hosts", list(dict.fromkeys(default_allowed_hosts))),
            allowed_origins=ts.get("allowed_origins", list(dict.fromkeys(default_allowed_origins))),
        )
    except TypeError:
        return TransportSecuritySettings(enable_dns_rebinding_protection=False)


def hash_password_cli():
    import getpass
    pw = getpass.getpass("Password: ")
    if pw != getpass.getpass("Confirm: "): print("Mismatch"); raise SystemExit(1)
    salt = secrets.token_hex(16)
    print('\nAdd to config.json → "oauth":')
    print(f'  "password_salt": "{salt}",')
    print(f'  "password_hash": "{_hash_pw(pw, salt)}"')

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--config",        default=DEFAULT_CONFIG)
    p.add_argument("--host",          default=None)
    p.add_argument("--port",          type=int, default=None)
    p.add_argument("--internal-port", type=int, default=None)
    p.add_argument("--transport",     default=None, choices=["sse","streamable-http","stdio"])
    p.add_argument("--hash-password", action="store_true")
    return p.parse_args()


def main():
    global CONFIG, mcp
    args = parse_args()
    if args.hash_password:
        hash_password_cli(); return

    CONFIG = load_config(args.config)
    init_roots(CONFIG)

    global TOKEN_STORE_PATH
    store = CONFIG.get("oauth", {}).get("token_store_path", "tokens.json")
    TOKEN_STORE_PATH = (Path(args.config).expanduser().resolve().parent / store).resolve()
    _load_tokens()

    sc         = CONFIG.get("server",{})
    transport  = args.transport or sc.get("transport", DEFAULT_TRANSPORT)
    host       = args.host      or sc.get("host", DEFAULT_SERVER_HOST)
    port       = int(args.port  or sc.get("port", DEFAULT_SERVER_PORT))
    internal_port = int(args.internal_port or sc.get("internal_port", _fallback_internal_port(port)))
    server_cfg = CONFIG.setdefault("server", {})
    server_cfg["host"] = host
    server_cfg["port"] = port
    server_cfg["transport"] = transport
    server_cfg["internal_port"] = internal_port

    ts_obj = make_ts(CONFIG)
    kw: Dict[str, Any] = {"host": host, "port": port}
    if ts_obj: kw["transport_security"] = ts_obj
    try:
        mcp = FastMCP("CodeGate", **kw)
    except TypeError:
        mcp = FastMCP("CodeGate")
        try: mcp.settings.host = host; mcp.settings.port = port
        except Exception: pass

    register_tools(mcp)

    log.info(f"Requested transport : {transport}")

    if transport == "stdio":
        mcp.run(transport="stdio")
        return

    if not HAS_STARLETTE:
        log.warning("starlette/uvicorn not installed — running without OAuth")
        mcp.run(transport=transport)
        return

    mcp_asgi = None
    selected_asgi_attr: Optional[str] = None

    if transport == "streamable-http":
        search_attrs = ("get_asgi_app", "http_app", "streamable_http_app", "asgi_app", "app", "sse_app")
    else:
        search_attrs = ("get_asgi_app", "sse_app", "http_app", "asgi_app", "app")

    for attr in search_attrs:
        try:
            v = getattr(mcp, attr, None)
            if v is None: continue
            mcp_asgi = v() if callable(v) else v
            if mcp_asgi is not None:
                selected_asgi_attr = attr
                log.info(f"MCP ASGI via: {attr}")
                break
        except Exception:
            continue

    if mcp_asgi is None or (transport == "streamable-http" and
                             selected_asgi_attr not in ("get_asgi_app", "http_app", "streamable_http_app")):
        if mcp_asgi is not None:
            log.warning("Got SSE app but transport=streamable-http — switching to thread+proxy")
        else:
            log.warning("Could not get MCP ASGI app — using thread+proxy fallback on the internal MCP port")
        if transport == "streamable-http":
            transport = "sse"
            CONFIG["server"]["transport"] = transport
            log.warning("streamable-http is unavailable in this FastMCP build; advertising SSE instead")
        if internal_port == port:
            raise ValueError("server.internal_port must be different from server.port")
        mcp_asgi = None
        import threading, httpx

        mcp_port = internal_port

        def run_mcp():
            try: mcp.settings.host = host; mcp.settings.port = mcp_port
            except Exception: pass
            mcp.run(transport="sse")

        t = threading.Thread(target=run_mcp, daemon=True)
        t.start()
        time.sleep(1.5)

        async def proxy_to_mcp(scope, receive, send):
            path    = scope.get("path","")
            method  = scope.get("method","GET")
            headers = dict(scope.get("headers",[]))
            qs      = scope.get("query_string",b"").decode()
            url     = f"http://{host}:{mcp_port}{path}"
            if qs: url += "?" + qs

            if scope["type"] == "http":
                body = b""
                while True:
                    msg = await receive()
                    body += msg.get("body", b"")
                    if not msg.get("more_body"): break

                async with httpx.AsyncClient(timeout=None) as client:
                    accept = headers.get(b"accept", b"").decode()
                    if path in ("/sse", "/mcp") or "text/event-stream" in accept:
                        async with client.stream(method, url, content=body,
                                                  headers={k.decode():v.decode() for k,v in headers.items() if k != b"host"}) as r:
                            await send({"type":"http.response.start","status":r.status_code,
                                        "headers":[[k.encode(),v.encode()] for k,v in r.headers.items()]})
                            async for chunk in r.aiter_bytes():
                                await send({"type":"http.response.body","body":chunk,"more_body":True})
                            await send({"type":"http.response.body","body":b"","more_body":False})
                    else:
                        r = await client.request(method, url, content=body,
                                                  headers={k.decode():v.decode() for k,v in headers.items() if k != b"host"})
                        await send({"type":"http.response.start","status":r.status_code,
                                    "headers":[[k.encode(),v.encode()] for k,v in r.headers.items()]})
                        await send({"type":"http.response.body","body":r.content})

        mcp_asgi = proxy_to_mcp
    log.info(f"Effective transport : {transport}")
    log.info(f"Internal MCP port   : {internal_port}")
    log.info(f"Local               : {_local_transport_url(host, port, transport)}")
    log.info(f"Public              : {_public_transport_url(transport)}")

    oauth_app = Starlette(routes=[
        Route("/authorize",                                 ep_authorize,          methods=["GET"]),
        Route("/login",                                     ep_login,              methods=["POST"]),
        Route("/token",                                     ep_token,              methods=["POST"]),
        Route("/.well-known/oauth-authorization-server",   ep_metadata,           methods=["GET"]),
        Route("/.well-known/openid-configuration",         ep_openid_configuration, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource",     ep_protected_resource, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource/mcp", ep_protected_resource, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource/sse", ep_protected_resource, methods=["GET"]),
        Route("/health",                                    ep_health,             methods=["GET"]),
    ])

    async def combined(scope, receive, send):
        path = scope.get("path","")
        if any(path.startswith(p) for p in PUBLIC):
            await oauth_app(scope, receive, send)
        else:
            await BearerMiddleware(mcp_asgi)(scope, receive, send)

    log.info(f"OAuth      : {_public_base_url()}/authorize")
    log.info(f"Token      : {_public_base_url()}/token")
    uvicorn.run(combined, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
