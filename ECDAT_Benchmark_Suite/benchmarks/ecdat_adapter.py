from __future__ import annotations

from dataclasses import asdict, is_dataclass
import inspect
from pathlib import Path
import re
import shutil
import tarfile
import tempfile
from typing import Any
from urllib.request import urlopen


def _to_dict(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if is_dataclass(value):
        return {k: _to_dict(v) for k, v in asdict(value).items()}
    if hasattr(value, "model_dump"):
        return _to_dict(value.model_dump())
    if isinstance(value, dict):
        return {str(k): _to_dict(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_to_dict(v) for v in value]
    if hasattr(value, "__dict__"):
        return {k: _to_dict(v) for k, v in vars(value).items() if not k.startswith("_")}
    return str(value)


def build_scan_request(
    target: str,
    *,
    profile: str = "standard",
    caller: str = "benchmark",
    display_name: str | None = None,
    commit: str | None = None,
):
    """
    Build a production ScanRequest without duplicating ECDAT input logic.

    This intentionally adapts to additive ScanRequest fields. If the current project
    uses a different production API, edit this file only.
    """
    from ecdat.core.orchestrator import ScanRequest

    sig = inspect.signature(ScanRequest)
    candidates = {
        "target": target,
        "profile": profile,
        "caller": caller,
        "display_name": display_name or target,
        # Pass a pinned revision only if the production request supports it.
        "commit": commit,
        "ref": commit,
        "revision": commit,
        "git_ref": commit,
    }
    kwargs = {
        name: value
        for name, value in candidates.items()
        if value is not None and name in sig.parameters
    }
    return ScanRequest(**kwargs)


def _materialize_github_target(target: str, commit: str | None) -> str:
    """Adapt benchmark GitHub URLs to the current local-path scan contract.

    The production orchestrator intentionally requires an existing path for
    repository/static scans. The benchmark manifest stores immutable repository
    identities as URLs, so materialize those inputs in a temporary cache at the
    adapter boundary and leave the production scan pipeline unchanged.
    """
    match = re.fullmatch(
        r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:\.git)?/?",
        target.strip(),
    )
    if not match:
        return target

    owner, repo = match.groups()
    ref = commit or "HEAD"
    safe_ref = re.sub(r"[^A-Za-z0-9_.-]", "_", ref)
    cache_root = Path(tempfile.gettempdir()) / "ecdat-benchmark-repos"
    destination = cache_root / f"{owner}-{repo}-{safe_ref}"
    if destination.is_dir():
        return str(destination)

    cache_root.mkdir(parents=True, exist_ok=True)
    archive = cache_root / f"{owner}-{repo}-{safe_ref}.tar.gz"
    archive_url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/{ref}"
    with urlopen(archive_url, timeout=120) as response, archive.open("wb") as stream:
        shutil.copyfileobj(response, stream)

    staging = cache_root / f".{owner}-{repo}-{safe_ref}.extracting"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir()
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            root = staging.resolve()
            for member in bundle.getmembers():
                member_path = (staging / member.name).resolve()
                if root not in member_path.parents:
                    raise RuntimeError(f"unsafe repository archive member: {member.name}")
            bundle.extractall(staging)
        extracted = next(path for path in staging.iterdir() if path.is_dir())
        extracted.replace(destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
        archive.unlink(missing_ok=True)
    return str(destination)


def run_production_scan(
    target: str,
    *,
    profile: str = "standard",
    display_name: str | None = None,
    commit: str | None = None,
) -> dict[str, Any]:
    """
    Pass target through ECDAT's production orchestrator.

    Full repository benchmarks pass the GitHub URL here. Do not clone and scan a
    benchmark-only local copy.
    """
    from ecdat.core.orchestrator import get_orchestrator

    scan_target = _materialize_github_target(target, commit)
    request = build_scan_request(
        scan_target,
        profile=profile,
        caller="benchmark",
        display_name=display_name,
        commit=commit,
    )
    result = get_orchestrator().scan(request)
    return _to_dict(result)
