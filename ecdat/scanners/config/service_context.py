"""Graph-linkable service context for config findings (Phase 5).

The per-format config scanners stay focused on extraction; this module
adds ONE post-pass (called by the config dispatcher) that derives, per
file, the join keys Phase 9 graph reconstruction needs:

    service=<name>     service / vhost / listener / resource identity
    listener=<addr>    ports / sockets the service listens on
    endpoint=<url>     advertised URLs
    cert_ref=<path>    referenced certificate files / ARNs / secret names
    key_ref=<path>     referenced private-key files / KMS key ids
    kms_ref=<id>       KMS / KeyVault key references

Keys ride in ``Context.notes`` (``k=v; k=v`` convention shared with the
dependency capability notes) so no CIR schema change is needed. Only
observed values are recorded; nothing is invented.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

__all__ = [
    "file_service_context",
    "attach_service_context",
    "format_notes",
]

_LISTEN_RE = re.compile(r"listen\s+([^;]+);", re.IGNORECASE)
_SERVER_NAME_RE = re.compile(r"server_name\s+([^;]+);", re.IGNORECASE)
_VHOST_RE = re.compile(r"<VirtualHost\s+([^>]+)>", re.IGNORECASE)
_APACHE_SERVER_NAME_RE = re.compile(r"^\s*ServerName\s+(\S+)", re.IGNORECASE | re.MULTILINE)
_URL_RE = re.compile(r"https?://[A-Za-z0-9_.\-:/?#=&%+~]+")
_ARN_RE = re.compile(r"arn:aws:[A-Za-z0-9_.\-/:+=@]+")
_KMS_ALIAS_RE = re.compile(r"\balias/[A-Za-z0-9/_+=.@-]+")
_CERT_PATH_RE = re.compile(
    r"(/[A-Za-z0-9_.\-/~]+?\.(?:pem|crt|cer|der|key|p12|pfx|jks))", re.IGNORECASE)
_SECRET_NAME_RE = re.compile(r"secretName\s*:\s*([A-Za-z0-9_.\-]+)")
_TF_RESOURCE_RE = re.compile(
    r'resource\s+"([A-Za-z0-9_]+)"\s+"([A-Za-z0-9_\-./]+)"')
_ENVOY_LISTENER_RE = re.compile(r'"name"\s*:\s*"([^"]+)"')
_ENVOY_ADDR_RE = re.compile(
    r'"(?:address|port_value)"\s*:\s*"?([A-Za-z0-9_.\-]+)"?')
_ENV_ASSIGN_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$")


def format_notes(pairs: list[tuple[str, str]]) -> str:
    """Render ordered ``k=v`` pairs (deduped, truncated values)."""
    seen: set[str] = set()
    parts: list[str] = []
    for key, value in pairs:
        value = " ".join(str(value or "").split())
        if not value or len(value) > 200:
            continue
        item = f"{key}={value}"
        if item not in seen:
            seen.add(item)
            parts.append(item)
    return "; ".join(parts)


def file_service_context(file_path: Path) -> dict[str, list[str]]:
    """Derive join keys from one config file (never raises)."""
    ctx: dict[str, list[str]] = {"service": [], "listener": [],
                                 "endpoint": [], "cert_ref": [],
                                 "key_ref": [], "kms_ref": []}
    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ctx
    name = file_path.name.lower()
    try:
        if name.endswith(".conf") or "nginx" in name:
            _nginx_context(text, ctx)
        if "apache" in name or name.endswith(".conf"):
            _apache_context(text, ctx)
        if name.endswith((".yaml", ".yml")):
            _k8s_context(text, ctx)
            _envoy_context(text, ctx)
        if name.endswith(".tf"):
            _terraform_context(text, ctx)
        if name == "openssl.cnf" or name.endswith(".cnf"):
            _openssl_cnf_context(text, file_path, ctx)
        if name.startswith(".env") or name.endswith(".env"):
            _env_context(text, ctx)
        for found in _URL_RE.findall(text):
            ctx["endpoint"].append(found)
        for found in _ARN_RE.findall(text):
            (ctx["kms_ref"] if ":kms:" in found or ":acm:" in found
             else ctx["cert_ref"]).append(found)
        for found in _KMS_ALIAS_RE.findall(text):
            ctx["kms_ref"].append(found.strip())
        if not ctx["service"]:
            ctx["service"].append(file_path.stem)
    except Exception:
        pass
    for key in ctx:
        seen: set[str] = set()
        ctx[key] = [v for v in ctx[key] if not (v in seen or seen.add(v))]
    return ctx


def _nginx_context(text: str, ctx: dict[str, list[str]]) -> None:
    for match in _SERVER_NAME_RE.finditer(text):
        for token in match.group(1).split():
            if token != "_":
                ctx["service"].append(token)
    for match in _LISTEN_RE.finditer(text):
        ctx["listener"].append(match.group(1).strip())


def _apache_context(text: str, ctx: dict[str, list[str]]) -> None:
    for match in _VHOST_RE.finditer(text):
        ctx["listener"].append(match.group(1).strip())
    for match in _APACHE_SERVER_NAME_RE.finditer(text):
        ctx["service"].append(match.group(1))


def _k8s_context(text: str, ctx: dict[str, list[str]]) -> None:
    try:
        import yaml
        docs = list(yaml.safe_load_all(text))
    except Exception:
        docs = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        meta = doc.get("metadata", {}) if isinstance(
            doc.get("metadata"), dict) else {}
        if meta.get("name"):
            ctx["service"].append(
                f"{str(doc.get('kind', 'Object')).lower()}/{meta['name']}")
        spec = doc.get("spec", {})
        if isinstance(spec, dict):
            for rule in spec.get("rules", []) or []:
                if isinstance(rule, dict) and rule.get("host"):
                    ctx["endpoint"].append(f"https://{rule['host']}")
            for tls in spec.get("tls", []) or []:
                if isinstance(tls, dict):
                    for host in tls.get("hosts", []) or []:
                        ctx["endpoint"].append(f"https://{host}")
                    if tls.get("secretName"):
                        ctx["cert_ref"].append(str(tls["secretName"]))
    for match in _SECRET_NAME_RE.finditer(text):
        ctx["cert_ref"].append(match.group(1))


def _envoy_context(text: str, ctx: dict[str, list[str]]) -> None:
    if "envoy" not in text.lower() and "filter_chains" not in text:
        return
    for match in _ENVOY_LISTENER_RE.finditer(text):
        ctx["service"].append(f"listener/{match.group(1)}")
    for match in _ENVOY_ADDR_RE.finditer(text):
        ctx["listener"].append(match.group(1))


def _terraform_context(text: str, ctx: dict[str, list[str]]) -> None:
    for match in _TF_RESOURCE_RE.finditer(text):
        ctx["service"].append(f"{match.group(1)}.{match.group(2)}")


def _openssl_cnf_context(text: str, file_path: Path,
                         ctx: dict[str, list[str]]) -> None:
    section = re.search(r"^\s*\[\s*([^\]]+)\s*\]", text, re.MULTILINE)
    ctx["service"].append(
        f"{file_path.stem}:{section.group(1)}" if section else file_path.stem)


def _env_context(text: str, ctx: dict[str, list[str]]) -> None:
    for line in text.splitlines():
        match = _ENV_ASSIGN_RE.match(line)
        if not match:
            continue
        key, value = match.group(1).upper(), match.group(2).strip("\"'")
        if key in ("SERVICE_NAME", "APP_NAME", "SERVICE"):
            ctx["service"].append(value)
        elif key in ("HOST", "HOSTNAME", "LISTEN", "PORT", "BIND"):
            ctx["listener"].append(value)
        elif "URL" in key and value.startswith(("http", "postgres", "mysql",
                                                "redis", "mongo", "amqp")):
            ctx["endpoint"].append(value)
        elif any(k in key for k in ("KMS", "KEY_ID", "KEY_ARN", "VAULT")):
            ctx["kms_ref"].append(value)
        elif any(k in key for k in ("CERT", "TLS_CERT", "SSL_CERT")):
            ctx["cert_ref"].append(value)
        elif any(k in key for k in ("KEY_FILE", "TLS_KEY", "SSL_KEY",
                                    "PRIVATE_KEY_FILE")):
            ctx["key_ref"].append(value)


def refs_from_detail(detail: str) -> dict[str, list[str]]:
    """Join keys observable in one finding's detail text."""
    refs: dict[str, list[str]] = {"cert_ref": [], "key_ref": [],
                                  "kms_ref": [], "endpoint": []}
    text = str(detail or "")
    lowered = text.lower()
    for match in _CERT_PATH_RE.finditer(text):
        (refs["key_ref"] if "key" in lowered else refs["cert_ref"]
         ).append(match.group(1))
    for match in _ARN_RE.findall(text):
        (refs["kms_ref"] if ":kms:" in match or ":acm:" in match
         else refs["cert_ref"]).append(match)
    for match in _URL_RE.findall(text):
        refs["endpoint"].append(match)
    return refs


def attach_service_context(findings: list) -> None:
    """Append per-file join keys to finding Context.notes (in place).

    Additive only: existing notes are preserved, keys are never
    duplicated, and files that fail to parse keep their findings
    untouched.
    """
    by_file: dict[str, list] = {}
    for finding in findings:
        loc = getattr(finding, "location", None)
        path = str(getattr(loc, "file", "") or "")
        if path:
            by_file.setdefault(path, []).append(finding)
    cache: dict[str, dict[str, list[str]]] = {}
    for path, group in by_file.items():
        try:
            file_ctx = cache.get(path)
            if file_ctx is None:
                file_ctx = file_service_context(Path(path))
                cache[path] = file_ctx
            file_pairs: list[tuple[str, str]] = []
            for key in ("service", "listener", "endpoint"):
                for value in file_ctx.get(key, [])[:4]:
                    file_pairs.append((key, value))
            for finding in group:
                # Per-finding scope: finding-specific refs must never leak
                # into sibling findings from the same file.
                pairs = list(file_pairs)
                for key in ("cert_ref", "key_ref", "kms_ref", "endpoint"):
                    for value in file_ctx.get(key, [])[:4]:
                        pairs.append((key, value))
                for key, values in refs_from_detail(
                        _finding_detail(finding)).items():
                    for value in values[:2]:
                        pairs.append((key, value))
                notes = format_notes(pairs)
                if not notes:
                    continue
                _append_notes(finding, notes)
        except Exception:
            continue


def _finding_detail(finding: Any) -> str:
    try:
        return " ".join(str(getattr(ev, "detail", "") or "")
                        for ev in (finding.evidence or []))
    except Exception:
        return ""


def _append_notes(finding: Any, notes: str) -> None:
    try:
        context = getattr(finding, "context", None)
        if context is None:
            return
        existing = str(getattr(context, "notes", "") or "")
        if not existing:
            context.notes = notes
        else:
            additions = [p for p in notes.split("; ")
                         if p.split("=")[0] + "=" not in existing]
            if additions:
                context.notes = existing + "; " + "; ".join(additions)
    except Exception:
        pass
