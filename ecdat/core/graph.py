"""Crypto Knowledge Graph builder (Person-1 Agent C).

Stdlib-only. No DB, no network. Builds an in-memory property graph from
CIR-shaped dicts and serves indexed O(V+E) / dict-lookup queries.

Planned CIR shape (defensive; works with plain dicts until
``ecdat.core.cir_models`` / ``registry`` / ``fusion`` / ``operations`` /
``scheduler`` / ``cir_validate`` land — none of those modules are imported
here so this file works standalone):

    operation = {
        "operation_id" | "id": str,
        "operation_type": Encrypt|Decrypt|Sign|Verify|KeyExchange|Hash|KDF|TLS|Storage,
        "canonical_name" | "algorithm": str,   # e.g. "RSA", "AES-128-ECB"
        "key_size" | "keySize": int | None,
        "curve" | "protocol_version" | ...: optional params,
        "usage_state": Confirmed|Probable|Possible|ProvidedOnly|Suppressed...,
        "confidence": float | None,
        "location": {"file","line","function","service","endpoint",
                     "image_digest","binary_offset","cloud_resource_id",
                     "config_path", ...},
        "implementation": {"role": uses|provides, "library","version",
                           "provider","api","binary_symbol","package",
                           "container_layer","image", ...},
        "context": {"exposure","criticality"|"business_criticality",
                    "owner","environment","service", ...},
        "material": {"key_id","cert_id","kms_key_id","key_fingerprint",
                     "cert_fingerprint", ...},
        "evidence": [ {...}, ... ],
        "asset_id" | "asset_ids": str | [str],
    }

Node types: Service, ContainerImage, Library, CryptoOperation, CryptoAsset,
Key, Certificate, Endpoint, CloudResource, Config, Owner.

Relations: runs_in, contains, provides, uses, implements, configures,
protects, exposes, manages, owns, depends_on, duplicates_of.

Derivation rules (only from data present on the operation — no invented
nodes; an op without a service name simply gets no Service node/edge):
  Service --uses--> CryptoOperation            (location/context service)
  Service --runs_in--> ContainerImage          (location.image_digest ...)
  Service --exposes--> Endpoint                (location.endpoint)
  ContainerImage --contains--> Library         (image + library present)
  Library --provides--> CryptoAsset            (implementation.library)
  CryptoOperation --implements--> CryptoAsset  (always)
  CryptoOperation --depends_on--> Library      (implementation.library)
  Config --configures--> Service | CryptoOperation
  Key --protects--> CryptoOperation            (material key ids)
  Certificate --protects--> Endpoint | CryptoOperation
  CloudResource --manages--> Key | Certificate (cloud ids present)
  Owner --owns--> Service | CryptoOperation    (context.owner)
  CryptoOperation --duplicates_of--> CryptoOperation (shared asset, id chain)

All passes are linear; GraphIndex holds dict indexes for queries.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque

__all__ = ["build_graph", "GraphIndex", "to_cir_graph", "graph_index_for_cir",
           "wire_system_links",
           "NODE_TYPES", "RELATIONS", "CIR_KIND_FOR", "CIR_REL_FOR"]

NODE_TYPES = frozenset({
    "Service", "ContainerImage", "Library", "CryptoOperation", "CryptoAsset",
    "Key", "Certificate", "Endpoint", "CloudResource", "Config", "Owner",
})

RELATIONS = frozenset({
    "runs_in", "contains", "provides", "uses", "implements", "configures",
    "protects", "exposes", "manages", "owns", "depends_on", "duplicates_of",
})

# Exposure values treated as internet-facing by GraphIndex.internet_facing().
_INTERNET_EXPOSURES = {"internet-facing", "internet", "public", "external"}


# --------------------------------------------------------------------------
# small defensive accessors (plain-dict CIR tolerance)
# --------------------------------------------------------------------------

def _as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _first_str(mapping: dict, *keys) -> str | None:
    """First non-empty string value for any of *keys* (also unwraps 1-lists)."""
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, (list, tuple)) and len(value) == 1:
            value = value[0]
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _first_num(mapping: dict, *keys):
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            return value
    return None


def _slug(text: str) -> str:
    """Deterministic id fragment: trim + collapse whitespace to '-'."""
    return re.sub(r"\s+", "-", text.strip())


def _op_id(op: dict, index: int) -> str:
    op_id = _first_str(op, "operation_id", "id", "op_id")
    return op_id if op_id else f"op-unknown-{index}"


def _op_node(op_id: str) -> str:
    return op_id if op_id.startswith("op:") else f"op:{op_id}"


def _asset_node(aid: str) -> str:
    return aid if aid.startswith(("asset:", "ast:")) else f"asset:{aid}"


def _canonical(op: dict) -> str:
    name = _first_str(op, "canonical_name", "algorithm", "name", "family")
    return name if name else "UNKNOWN"


def _asset_ids_for(op: dict, op_id: str, canonical: str) -> list[str]:
    """Explicit asset link(s) when present, else a deterministic slug."""
    raw = op.get("asset_ids", op.get("asset_id"))
    if isinstance(raw, str) and raw.strip():
        return [raw.strip()]
    if isinstance(raw, (list, tuple)):
        ids = [str(x).strip() for x in raw if str(x).strip()]
        if ids:
            return sorted(set(ids))
    # Fallback slug from canonical + distinguishing params (stable, readable).
    # (Bare slug: _asset_node() adds the "asset:" prefix exactly once.)
    loc = _as_dict(op.get("location"))
    impl = _as_dict(op.get("implementation"))
    bits = [canonical.lower()]
    key_size = _first_num(op, "key_size", "keySize", "bits")
    if key_size is not None:
        bits.append(str(int(key_size)))
    for key in ("curve", "mode", "protocol_version", "variant"):
        val = _first_str(op, key)
        if val:
            bits.append(val.lower())
    lib = _first_str(impl, "library")
    if (_first_str(impl, "role") or "").lower() == "provides" and lib:
        bits.append("provided-by-" + lib.lower())
    scope = _first_str(loc, "service") or _first_str(_as_dict(op.get("context")), "service")
    if scope:
        bits.append("svc-" + scope.lower())
    return [_slug("-".join(bits))]


def _cir_lists(operations, assets, contexts):
    """Tolerate a whole-CIR dict passed as the first argument."""
    if isinstance(operations, dict) and assets is None and contexts is None:
        cir = operations
        return (
            cir.get("operations", []) or [],
            cir.get("assets", []) or [],
            cir.get("contexts", []) or [],
        )
    return (operations or [], assets or [], contexts or [])


# --------------------------------------------------------------------------
# graph builder
# --------------------------------------------------------------------------

def build_graph(operations, assets=None, contexts=None) -> dict:
    """Build ``{nodes:[{id,type,label,meta}], edges:[{from_id,to_id,relation}]}``.

    Deterministic: nodes/edges deduped by id / (from,to,relation) triple and
    emitted sorted by (id) / (from_id, to_id, relation). Single linear pass
    over operations plus linear passes over assets/contexts: O(V+E).
    """
    operations, assets, contexts = _cir_lists(operations, assets, contexts)

    nodes: dict[str, dict] = {}
    edges: dict[tuple, dict] = {}

    def add_node(node_id: str, ntype: str, label: str, meta: dict | None = None):
        if ntype not in NODE_TYPES:
            raise ValueError(f"unknown node type: {ntype!r}")
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "type": ntype,
                              "label": label, "meta": dict(meta or {})}
        else:  # merge meta monotonically (first writer wins per key)
            for key, val in (meta or {}).items():
                nodes[node_id]["meta"].setdefault(key, val)

    def add_edge(from_id: str, to_id: str, relation: str):
        if relation not in RELATIONS:
            raise ValueError(f"unknown relation: {relation!r}")
        key = (from_id, to_id, relation)
        if key not in edges:
            edges[key] = {"from_id": from_id, "to_id": to_id,
                          "relation": relation}

    # -- standalone assets / contexts first (so op pass can link to them) --
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        aid = _first_str(asset, "asset_id", "id") or _slug(_canonical(asset))
        add_node(_asset_node(aid), "CryptoAsset",
                 _first_str(asset, "canonical_name", "algorithm", "name") or aid,
                 {"asset_id": aid,
                  "canonical_name": _first_str(asset, "canonical_name", "algorithm") or aid,
                  **{k: v for k, v in asset.items()
                     if k not in ("asset_id", "id") and isinstance(v, (str, int, float, bool))}})

    for ctx in contexts:
        if not isinstance(ctx, dict):
            continue
        svc = _first_str(ctx, "service")
        owner = _first_str(ctx, "owner")
        endpoint = _first_str(ctx, "endpoint")
        cloud = _first_str(ctx, "cloud_resource_id", "cloud_resource")
        image = _first_str(ctx, "image_digest", "image")
        if svc:
            add_node(f"svc:{_slug(svc)}", "Service", svc, {"service": svc})
        if owner:
            add_node(f"owner:{_slug(owner)}", "Owner", owner, {"owner": owner})
            if svc:
                add_edge(f"owner:{_slug(owner)}", f"svc:{_slug(svc)}", "owns")
        if endpoint:
            add_node(f"ep:{_slug(endpoint)}", "Endpoint", endpoint,
                     {"endpoint": endpoint,
                      "exposure": _first_str(ctx, "exposure") or "internal"})
            if svc:
                add_edge(f"svc:{_slug(svc)}", f"ep:{_slug(endpoint)}", "exposes")
        if cloud:
            add_node(f"cloud:{_slug(cloud)}", "CloudResource", cloud,
                     {"cloud_resource_id": cloud})
        if image:
            add_node(f"img:{_slug(image)}", "ContainerImage", image,
                     {"image_digest": image})
            if svc:
                add_edge(f"svc:{_slug(svc)}", f"img:{_slug(image)}", "runs_in")

    # -- operations (main pass) --
    asset_to_ops: dict[str, list[str]] = defaultdict(list)

    for index, op in enumerate(operations):
        if not isinstance(op, dict):
            continue
        op_id = _op_id(op, index)
        canonical = _canonical(op)
        op_node = _op_node(op_id)
        usage_state = _first_str(op, "usage_state", "usageState", "state") or "Possible"
        add_node(op_node, "CryptoOperation", f"{canonical} [{op_id}]",
                 {"operation_id": op_id, "canonical_name": canonical,
                  "operation_type": _first_str(op, "operation_type", "type") or "Encrypt",
                  "usage_state": usage_state,
                  "confidence": _first_num(op, "confidence")})

        loc = _as_dict(op.get("location"))
        impl = _as_dict(op.get("implementation"))
        ctx = _as_dict(op.get("context"))
        mat = _as_dict(op.get("material"))

        # CryptoAsset link (one op may reference several assets).
        for aid in _asset_ids_for(op, op_id, canonical):
            asset_node = _asset_node(aid)
            if asset_node not in nodes:
                add_node(asset_node, "CryptoAsset", canonical,
                         {"asset_id": aid, "canonical_name": canonical})
            add_edge(op_node, asset_node, "implements")
            asset_to_ops[asset_node].append(op_node)

        # Service (+ uses edge).
        service = (_first_str(loc, "service") or _first_str(ctx, "service")
                   or _first_str(impl, "service"))
        svc_node = None
        if service:
            svc_node = f"svc:{_slug(service)}"
            if svc_node not in nodes:
                add_node(svc_node, "Service", service, {"service": service})
            add_edge(svc_node, op_node, "uses")

        # ContainerImage (+ runs_in / contains).
        image = (_first_str(loc, "image_digest", "image", "image_digest_or_layer")
                 or _first_str(impl, "container_layer", "image", "image_digest"))
        img_node = None
        if image:
            img_node = f"img:{_slug(image)}"
            if img_node not in nodes:
                add_node(img_node, "ContainerImage", image, {"image_digest": image})
            if svc_node:
                add_edge(svc_node, img_node, "runs_in")

        # Library (+ provides / depends_on / contains).
        library = _first_str(impl, "library", "provider", "package")
        lib_node = None
        if library:
            version = _first_str(impl, "version")
            lib_node = f"lib:{_slug(library)}@{_slug(version)}" if version else f"lib:{_slug(library)}"
            if lib_node not in nodes:
                add_node(lib_node, "Library",
                         f"{library}@{version}" if version else library,
                         {"library": library, **({"version": version} if version else {})})
            add_edge(op_node, lib_node, "depends_on")
            if img_node:
                add_edge(img_node, lib_node, "contains")
            for aid in _asset_ids_for(op, op_id, canonical):
                add_edge(lib_node, _asset_node(aid), "provides")

        # Key (+ protects; CloudResource manages when cloud-linked).
        key_ref = _first_str(mat, "key_id", "kms_key_id", "key_fingerprint",
                             "keystore_id", "key")
        cloud_ref = (_first_str(loc, "cloud_resource_id", "cloud_resource")
                     or _first_str(mat, "kms_key_id", "cloud_resource_id")
                     or _first_str(ctx, "cloud_resource_id", "cloud_resource"))
        cloud_node = None
        if cloud_ref:
            cloud_node = f"cloud:{_slug(cloud_ref)}"
            if cloud_node not in nodes:
                add_node(cloud_node, "CloudResource", cloud_ref,
                         {"cloud_resource_id": cloud_ref})
        if key_ref:
            key_node = f"key:{_slug(key_ref)}"
            if key_node not in nodes:
                add_node(key_node, "Key", key_ref, {"key_id": key_ref})
            add_edge(key_node, op_node, "protects")
            if cloud_node:
                add_edge(cloud_node, key_node, "manages")

        # Certificate (+ protects endpoint or op).
        cert_ref = _first_str(mat, "cert_id", "cert_fingerprint",
                              "certificate_id", "certificate")
        endpoint = _first_str(loc, "endpoint", "url", "service_url")
        ep_node = None
        if endpoint:
            ep_node = f"ep:{_slug(endpoint)}"
            if ep_node not in nodes:
                add_node(ep_node, "Endpoint", endpoint,
                         {"endpoint": endpoint,
                          "exposure": _first_str(ctx, "exposure", "environment_exposure")
                          or _first_str(loc, "exposure") or "internal"})
            if svc_node:
                add_edge(svc_node, ep_node, "exposes")
        if cert_ref:
            cert_node = f"cert:{_slug(cert_ref)}"
            if cert_node not in nodes:
                add_node(cert_node, "Certificate", cert_ref, {"cert_id": cert_ref})
            add_edge(cert_node, ep_node if ep_node else op_node, "protects")
            if cloud_node:
                add_edge(cloud_node, cert_node, "manages")

        # Config (+ configures service or op).
        config = _first_str(loc, "config_path", "config_file", "config")
        if config:
            cfg_node = f"cfg:{_slug(config)}"
            if cfg_node not in nodes:
                add_node(cfg_node, "Config", config, {"config_path": config})
            add_edge(cfg_node, svc_node if svc_node else op_node, "configures")

        # Owner (+ owns service or op).
        owner = _first_str(ctx, "owner")
        if owner:
            owner_node = f"owner:{_slug(owner)}"
            if owner_node not in nodes:
                add_node(owner_node, "Owner", owner, {"owner": owner})
            add_edge(owner_node, svc_node if svc_node else op_node, "owns")

    # -- duplicates_of: ops sharing one asset, chained in sorted op-id order --
    for asset_node in sorted(asset_to_ops):
        ops = sorted(set(asset_to_ops[asset_node]))
        for first, second in zip(ops, ops[1:]):
            if first != second:
                add_edge(first, second, "duplicates_of")

    return {
        "nodes": [nodes[k] for k in sorted(nodes)],
        "edges": [edges[k] for k in sorted(edges)],
    }


# --------------------------------------------------------------------------
# CIR v0.1 wire bridge (cir.schema.json GraphNode/GraphEdge)
# --------------------------------------------------------------------------

# Rich node type -> wire kind. Lossy by design (wire has 7 kinds); the
# original rich id survives in `ref` so nothing is unrecoverable.
CIR_KIND_FOR = {
    "CryptoAsset": "asset",
    "CryptoOperation": "operation",
    "Service": "service",
    "Library": "library",
    "Key": "key",
    "ContainerImage": "host",
    "Endpoint": "host",
    "CloudResource": "host",
    "Certificate": "file",
    "Config": "file",
    "Owner": "service",
}

# Rich relation -> wire relationship. Rationale: runs_in/manages/owns are
# containment-ish; implements/provides/duplicates_of derive crypto from
# crypto; configures is a call into a service; exposes terminates at the
# network edge.
CIR_REL_FOR = {
    "uses": "uses",
    "depends_on": "depends_on",
    "contains": "contains",
    "protects": "protects",
    "runs_in": "contains",
    "implements": "derives",
    "provides": "derives",
    "configures": "calls",
    "exposes": "terminates",
    "manages": "contains",
    "owns": "contains",
    "duplicates_of": "derives",
}

_KIND_TO_TYPE = {
    "asset": "CryptoAsset",
    "operation": "CryptoOperation",
    "service": "Service",
    "library": "Library",
    "key": "Key",
    "host": "Endpoint",
    "file": "Config",
}
_REL_TO_RICH = {
    "uses": "uses",
    "depends_on": "depends_on",
    "contains": "contains",
    "protects": "protects",
    "derives": "implements",
    "calls": "configures",
    "terminates": "exposes",
}


def to_cir_graph(graph: dict) -> dict:
    """Project a rich ``build_graph`` result onto the CIR v0.1 wire shape.

    Returns ``{"nodes": [{id, kind, ref, label?}],
    "edges": [{from, to, relationship}]}`` validating against
    cir.schema.json GraphNode/GraphEdge (additionalProperties-safe: only
    schema keys emitted). Order is preserved from the input (already
    deterministic). ``ref`` carries the rich node id for lossless joins.
    """
    if not isinstance(graph, dict):
        raise TypeError("to_cir_graph expects a build_graph result dict")
    nodes = []
    for node in graph.get("nodes", []) or []:
        if not isinstance(node, dict) or not node.get("id"):
            continue
        ntype = node.get("type", node.get("kind", ""))
        kind = CIR_KIND_FOR.get(ntype)
        if kind is None:  # already-wire node: pass through (drop extras)
            if node.get("kind"):
                out = {"id": node["id"], "kind": node["kind"]}
                if node.get("ref"):
                    out["ref"] = node["ref"]
                if node.get("label"):
                    out["label"] = node["label"]
                nodes.append(out)
            continue
        out = {"id": node["id"], "kind": kind, "ref": node["id"]}
        if node.get("label"):
            out["label"] = node["label"]
        nodes.append(out)
    edges = []
    for edge in graph.get("edges", []) or []:
        if not isinstance(edge, dict):
            continue
        src = edge.get("from_id", edge.get("from"))
        dst = edge.get("to_id", edge.get("to"))
        rel = edge.get("relation", edge.get("relationship"))
        if not src or not dst:
            continue
        relationship = CIR_REL_FOR.get(rel, rel)
        if relationship not in ("uses", "calls", "contains", "derives",
                                "protects", "depends_on", "terminates"):
            continue  # never emit wire-invalid relationships
        edges.append({"from": src, "to": dst, "relationship": relationship})
    return {"nodes": nodes, "edges": edges}


def graph_index_for_cir(cir: dict) -> "GraphIndex":
    """Build a GraphIndex straight from a CIR v0.1 document's graph."""
    if not isinstance(cir, dict):
        raise TypeError("graph_index_for_cir expects a CIR document dict")
    return GraphIndex((cir.get("graph", {}) or {}).get("nodes", []),
                      (cir.get("graph", {}) or {}).get("edges", []))


def _normalize_wire_node(node: dict) -> dict:
    """Map a wire GraphNode onto the rich view (non-mutating)."""
    if node.get("type"):  # already rich
        return node
    kind = node.get("kind", "")
    ntype = _KIND_TO_TYPE.get(kind, kind)
    # Refine host/file back when the ref prefix tells the truth.
    ref = str(node.get("ref", "") or "")
    if kind == "host":
        if ref.startswith("img:"):
            ntype = "ContainerImage"
        elif ref.startswith("cloud:"):
            ntype = "CloudResource"
        elif ref.startswith("ep:") or "://" in ref:
            ntype = "Endpoint"
    elif kind == "file":
        if ref.startswith("cert:"):
            ntype = "Certificate"
        elif ref.startswith("cfg:"):
            ntype = "Config"
    elif kind == "service" and ref.startswith("owner:"):
        ntype = "Owner"
    meta = dict(node.get("meta", {}) or {})
    label = node.get("label", "")
    # Seed matchable meta from the label ("RSA [op-..]" / "RSA" / URLs).
    if label and "canonical_name" not in meta:
        head = str(label).split(" [")[0].strip()
        if head:
            meta.setdefault("canonical_name", head)
    if ref and ref not in meta.values():
        for key in ("operation_id", "asset_id", "service", "library",
                    "key_id", "cert_id", "endpoint"):
            if meta.get(key) == ref:
                break
        else:
            meta.setdefault("ref", ref)
    return {"id": node.get("id"), "type": ntype,
            "label": label or node.get("id", ""), "meta": meta}


def _normalize_wire_edge(edge: dict) -> dict:
    if edge.get("relation"):
        return edge
    return {"from_id": edge.get("from"), "to_id": edge.get("to"),
            "relation": _REL_TO_RICH.get(edge.get("relationship"),
                                         edge.get("relationship"))}


# --------------------------------------------------------------------------
# in-memory adjacency index + queries
# --------------------------------------------------------------------------

class GraphIndex:
    """Indexed view over a ``build_graph`` result.

    Construction is O(V+E). All queries are indexed dict lookups or a single
    BFS — no DB, designed for <1s on SIH-scale estates.

    Also accepts CIR v0.1 wire-shaped graphs (``GraphNode{id,kind,ref?,
    label?}`` / ``GraphEdge{from,to,relationship}`` per cir.schema.json):
    kinds/relationships are mapped back onto the rich vocabulary on load so
    queries work directly on stored CIR documents and sample files.
    """

    def __init__(self, nodes, edges=None) -> None:
        # Tolerate a whole {"nodes":..,"edges":..} graph dict as `nodes`.
        if isinstance(nodes, dict) and edges is None:
            edges = nodes.get("edges", [])
            nodes = nodes.get("nodes", [])
        # Normalize wire-shaped nodes/edges onto the rich view (no-op if
        # already rich). self.nodes keeps the normalized copies.
        self.nodes: list[dict] = [
            _normalize_wire_node(n) if isinstance(n, dict) else n
            for n in (nodes or [])
        ]
        self.edges: list[dict] = [
            _normalize_wire_edge(e) if isinstance(e, dict) else e
            for e in (edges or [])
        ]
        self.by_id: dict[str, dict] = {}
        self.by_type: dict[str, list[dict]] = defaultdict(list)
        self.out: dict[str, list[tuple[str, str]]] = defaultdict(list)
        self.inc: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for node in self.nodes:
            nid = node.get("id")
            if not nid or nid in self.by_id:
                continue
            self.by_id[nid] = node
            self.by_type[node.get("type", "")].append(node)
        for edge in self.edges:
            src, dst, rel = edge.get("from_id"), edge.get("to_id"), edge.get("relation")
            if src in self.by_id and dst in self.by_id:
                self.out[src].append((rel, dst))
                self.inc[dst].append((rel, src))

    # -- basics ---------------------------------------------------------
    def __len__(self) -> int:
        return len(self.by_id)

    def get(self, node_id: str) -> dict | None:
        return self.by_id.get(node_id)

    def nodes_of_type(self, ntype: str) -> list[dict]:
        return list(self.by_type.get(ntype, []))

    def neighbors(self, node_id: str, direction: str = "out") -> list[dict]:
        adj = self.out if direction != "in" else self.inc
        return [self.by_id[dst] for _, dst in adj.get(node_id, []) if dst in self.by_id]

    # -- queries ---------------------------------------------------------
    def risky_nodes(self, canonical_names) -> list[dict]:
        """CryptoOperation (+ linked CryptoAsset) nodes for given algorithms.

        ``canonical_names`` matched case-insensitively against node meta
        ``canonical_name`` / ``algorithm`` (wire graphs: seeded from the
        node label on load).
        """
        wanted = {str(n).strip().upper() for n in (canonical_names or []) if str(n).strip()}
        hits: dict[str, dict] = {}
        for node in self.nodes:
            if node.get("type") not in ("CryptoOperation", "CryptoAsset"):
                continue
            meta = node.get("meta", {}) if isinstance(node.get("meta"), dict) else {}
            for key in ("canonical_name", "algorithm", "name"):
                val = meta.get(key)
                if isinstance(val, str) and val.strip().upper() in wanted:
                    hits[node["id"]] = node
                    break
        return [hits[k] for k in sorted(hits)]

    def internet_facing(self) -> dict:
        """``{"endpoints": [...], "operations": [...]}`` exposed to internet."""
        endpoints = [
            n for n in self.by_type.get("Endpoint", [])
            if str((n.get("meta", {}) or {}).get("exposure", "internal")).strip().lower()
            in _INTERNET_EXPOSURES
        ]
        ep_ids = {n["id"] for n in endpoints}
        # Services exposing those endpoints...
        services = {src for ep in ep_ids for rel, src in self.inc.get(ep, [])
                    if rel == "exposes" and src in self.by_id}
        ops: dict[str, dict] = {}
        for svc in services:
            for rel, dst in self.out.get(svc, []):
                if rel == "uses" and dst in self.by_id:
                    ops[dst] = self.by_id[dst]
        # ...plus ops whose own meta exposure is internet-facing.
        for node in self.by_type.get("CryptoOperation", []):
            meta = node.get("meta", {}) if isinstance(node.get("meta"), dict) else {}
            if str(meta.get("exposure", "")).strip().lower() in _INTERNET_EXPOSURES:
                ops[node["id"]] = node
        return {
            "endpoints": sorted(endpoints, key=lambda n: n["id"]),
            "operations": [ops[k] for k in sorted(ops)],
        }

    def blast_radius(self, library) -> list[dict]:
        """CryptoOperation nodes affected by a library (``name`` or ``name@ver``).

        Matches ``depends_on`` edges plus operations implementing an asset the
        library ``provides``.
        """
        query = str(library or "").strip()
        name, _, version = query.partition("@")
        name = name.strip().lower()
        version = version.strip()
        libs = []
        for node in self.by_type.get("Library", []):
            meta = node.get("meta", {}) if isinstance(node.get("meta"), dict) else {}
            lib_name = str(meta.get("library", node.get("label", ""))).strip().lower()
            lib_ver = str(meta.get("version", "")).strip()
            if lib_name == name and (not version or lib_ver == version):
                libs.append(node["id"])
        affected: dict[str, dict] = {}
        for lib_id in libs:
            for rel, src in self.inc.get(lib_id, []):  # op --depends_on--> lib
                if rel == "depends_on" and src in self.by_id:
                    affected[src] = self.by_id[src]
            for rel, asset_id in self.out.get(lib_id, []):  # lib --provides--> asset
                if rel != "provides":
                    continue
                for rel2, op_id in self.inc.get(asset_id, []):  # op --implements--> asset
                    if rel2 == "implements" and op_id in self.by_id:
                        affected[op_id] = self.by_id[op_id]
        return [affected[k] for k in sorted(affected)]

    def trace(self, service_id: str) -> list[dict]:
        """BFS chain starting at a Service node (accepts ``svc:name`` or name)."""
        start = str(service_id or "").strip()
        if not start.startswith("svc:"):
            start = f"svc:{_slug(start)}" if start else ""
        if start not in self.by_id:
            return []
        seen = {start}
        order = [self.by_id[start]]
        queue: deque[str] = deque([start])
        while queue:
            current = queue.popleft()
            # Stable relation order => deterministic chain.
            for rel, dst in sorted(self.out.get(current, [])):
                if dst not in seen and dst in self.by_id:
                    seen.add(dst)
                    order.append(self.by_id[dst])
                    queue.append(dst)
        return order


# --------------------------------------------------------------------------
# Phase 9: production wire enrichment (authoritative system reconstruction)
# --------------------------------------------------------------------------

#: ``k=v`` join keys (Phase 5 service context, Phase 7 runtime/container
#: notes) understood by the wire enrichment below. Values are observed
#: detector output; nothing is invented here.
_WIRE_KV_KEYS = ("service", "endpoint", "image", "layer", "fingerprint",
                 "cert_ref", "key_ref", "kms_ref", "listener", "owner")

_WIRE_KV_RES = {key: re.compile(r"%s=([^;\r\n]+)" % re.escape(key))
                for key in _WIRE_KV_KEYS}

_URL_RE = re.compile(r"https?://[A-Za-z0-9_.\-:/?#=&%+~]+")
_SHA_FP_RE = re.compile(r"SHA256:(?:[0-9A-Fa-f]{2}:){10,}[0-9A-Fa-f]{2}")


def _wire_kv_all(text: str | None, key: str) -> list[str]:
    """All values recorded for ``key=`` in a notes/detail blob."""
    if not text:
        return []
    out: list[str] = []
    for match in _WIRE_KV_RES[key].finditer(str(text)):
        value = " ".join(match.group(1).split())
        if value and len(value) <= 200 and value not in out:
            out.append(value)
    return out


def _wire_evidence_texts(obj) -> list[str]:
    """Joinable text blobs from one asset/operation (notes + evidence)."""
    texts: list[str] = []
    try:
        notes = getattr(getattr(obj, "context", None), "notes", None)
        if notes:
            texts.append(str(notes))
    except Exception:
        pass
    try:
        for item in (getattr(obj, "evidence", None) or []):
            for attr in ("detail", "snippet"):
                try:
                    value = getattr(item, attr, None)
                except Exception:
                    value = None
                if value:
                    texts.append(str(value))
    except Exception:
        pass
    return texts


def _wire_first(values: list[str]) -> str:
    for value in values:
        if value:
            return value
    return ""


def wire_system_links(assets, operations) -> dict:
    """Cross-surface system links for fused CIR assets/operations.

    The authoritative Phase 9 enrichment: adapts the fused pydantic
    assets/operations (duck-typed via ``getattr`` so this module stays
    stdlib-only with no ``cir_models`` import) to the rich
    :func:`build_graph` contract, projects the result onto the CIR v0.1
    wire vocabulary with :func:`to_cir_graph`, and returns wire dicts::

        {"nodes": [{id, kind, ref, label?}],
         "edges": [{from, to, relationship}],
         "provenance": {node_id: "observed" | "inferred"},
         "counts": {"nodes": N, "edges": M, "observed": O, "inferred": I}}

    Only evidence-backed links are emitted (an operation without a
    service name gets no Service node; a fingerprint seen once links
    only its own object). A shared node referenced from more than one
    distinct file is marked ``inferred`` (cross-file linkage) in both
    ``provenance`` and the node ``ref`` (``inferred:<rich-id>``);
    single-file nodes are ``observed``. Labels of inferred nodes gain a
    `` (inferred)`` suffix so GUI/report surfaces stay honest.

    Never raises: any internal failure yields empty nodes/edges.
    """
    try:
        return _wire_system_links_inner(list(assets or []),
                                        list(operations or []))
    except Exception:
        return {"nodes": [], "edges": [], "provenance": {},
                "counts": {"nodes": 0, "edges": 0,
                           "observed": 0, "inferred": 0}}


def _wire_system_links_inner(assets: list, operations: list) -> dict:
    asset_by_id: dict[str, object] = {}
    for asset in assets:
        try:
            aid = str(getattr(asset, "asset_id", "") or "")
        except Exception:
            continue
        if aid:
            asset_by_id[aid] = asset

    # Basename index of scanned certificate files for cert_ref joins.
    cert_files: dict[str, str] = {}
    for asset in assets:
        try:
            tools = [str(getattr(e, "tool", "") or "")
                     for e in (getattr(asset, "evidence", None) or [])]
        except Exception:
            tools = []
        if not any(t.startswith("certificate-") for t in tools):
            continue
        try:
            loc = getattr(asset, "location", None)
            path = str(getattr(loc, "file", "") or "")
        except Exception:
            path = ""
        if path:
            base = path.replace("\\", "/").split("/")[-1].lower()
            if base:
                cert_files.setdefault(base, path)

    op_dicts: list[dict] = []
    asset_dicts: list[dict] = []
    key_files: dict[str, set[str]] = {}

    def _track(node_id: str, path: str) -> None:
        if node_id and path:
            key_files.setdefault(node_id, set()).add(path)

    for operation in operations:
        try:
            op_id = str(getattr(operation, "operation_id", "") or "")
            asset_id = str(getattr(operation, "asset_id", "") or "")
            op_type = str(getattr(getattr(operation, "operation_type", None),
                                  "value", None)
                          or getattr(operation, "operation_type", "")
                          or "Encrypt")
            confidence = float(getattr(operation, "confidence", 0.0) or 0.0)
        except Exception:
            continue
        if not op_id:
            continue
        asset = asset_by_id.get(asset_id)
        try:
            canonical = str(getattr(asset, "canonical", "") or "UNKNOWN")
        except Exception:
            canonical = "UNKNOWN"
        blobs = _wire_evidence_texts(operation)
        if asset is not None:
            blobs = blobs + _wire_evidence_texts(asset)
        joined = "\n".join(blobs)
        try:
            loc = getattr(operation, "location", None)
            path = str(getattr(loc, "file", "") or "") if loc else ""
            uri = str(getattr(loc, "uri", "") or "") if loc else ""
        except Exception:
            path, uri = "", ""
        services = _wire_kv_all(joined, "service")
        endpoints = _wire_kv_all(joined, "endpoint")
        if uri and "://" in uri and uri not in endpoints:
            endpoints.append(uri)
        for match in _URL_RE.finditer(joined):
            if match.group(0) not in endpoints:
                endpoints.append(match.group(0))
        images = _wire_kv_all(joined, "image")
        layers = _wire_kv_all(joined, "layer")
        fps = _wire_kv_all(joined, "fingerprint")
        cert_refs = _wire_kv_all(joined, "cert_ref")
        key_refs = _wire_kv_all(joined, "key_ref")
        kms_refs = _wire_kv_all(joined, "kms_ref")
        owners = _wire_kv_all(joined, "owner")
        service = _wire_first(services)
        endpoint = _wire_first(endpoints)
        image = _wire_first(images)
        # Container inner URIs (image:<ref>/layer:<digest>/<rel>) carry
        # the image identity even when notes are absent.
        if not image and path.startswith("image:"):
            image = path[len("image:"):].split("/layer:")[0].split("/")[0]
        cert_fp = _wire_first(
            [v for v in fps if _SHA_FP_RE.search(v)] + fps)
        cert_cfg = ""
        for ref in cert_refs + key_refs:
            base = ref.replace("\\", "/").split("/")[-1].lower()
            if base in cert_files:
                cert_cfg = cert_files[base]
                break
            if not cert_cfg and len(ref) <= 200:
                cert_cfg = ref
        key_id = _wire_first(
            [v for v in kms_refs + key_refs if v != cert_cfg])
        cloud = _wire_first(
            [v for v in kms_refs + cert_refs + key_refs
             if v.startswith("arn:")])
        try:
            impl = getattr(operation, "implementation", None)
            library = str(getattr(impl, "library", "") or "") if impl else ""
            version = str(getattr(impl, "version", "") or "") \
                if impl else ""
        except Exception:
            library, version = "", ""
        try:
            ctx = getattr(operation, "context", None)
            exposure = str(getattr(getattr(ctx, "exposure", None), "value",
                                   None)
                           or getattr(ctx, "exposure", "") or "")
        except Exception:
            exposure = ""
        try:
            key_size = getattr(asset, "key_size", None)
            mode = getattr(asset, "mode", None)
            curve = getattr(asset, "curve", None)
            protocol = getattr(asset, "protocol", None)
        except Exception:
            key_size = mode = curve = protocol = None
        try:
            usage = str(getattr(getattr(operation, "risk_inputs", None),
                                "usage_state", None) or "")
            if not usage or "." in usage:
                usage = usage.rsplit(".", 1)[-1]
        except Exception:
            usage = ""
        op_dict: dict = {
            "operation_id": op_id,
            "operation_type": op_type,
            "canonical_name": canonical,
            "asset_id": asset_id,
            "confidence": confidence,
            "usage_state": usage or "Possible",
            "location": {"file": path,
                         **({"service": service} if service else {}),
                         **({"endpoint": endpoint} if endpoint else {}),
                         **({"image": image} if image else {}),
                         **({"config": cert_cfg} if cert_cfg and service
                             else {})},
            "implementation": {
                **({"library": library} if library else {}),
                **({"version": version} if version else {}),
                **({"container_layer": _wire_first(layers)}
                   if layers else {}),
            },
            "context": {**({"service": service} if service else {}),
                        **({"owner": _wire_first(owners)}
                           if owners else {}),
                        **({"exposure": exposure} if exposure else {})},
            "material": {
                **({"key_id": key_id} if key_id else {}),
                **({"cert_fingerprint": cert_fp} if cert_fp else {}),
                **({"cloud_resource_id": cloud} if cloud else {}),
            },
        }
        op_dicts.append(op_dict)
        for prefix, key in (("svc:", service), ("ep:", endpoint),
                            ("img:", image),
                            ("key:", key_id),
                            ("cert:", cert_fp or cert_cfg),
                            ("cloud:", cloud),
                            ("owner:", _wire_first(owners))):
            if key:
                _track(prefix + _slug(key), path)

    for asset in assets:
        try:
            aid = str(getattr(asset, "asset_id", "") or "")
            canonical = str(getattr(asset, "canonical", "") or "")
        except Exception:
            continue
        if aid and canonical:
            asset_dicts.append({"asset_id": aid,
                                "canonical_name": canonical})

    rich = build_graph(op_dicts, asset_dicts, [])
    wire = to_cir_graph(rich)
    # Drop the op->asset derives edges the minimal rebuild already
    # expresses as USES (one link per semantic; no parallel dupes).
    op_ids = {d["operation_id"] for d in op_dicts}
    asset_ids = {d["asset_id"] for d in asset_dicts}
    nodes: list[dict] = []
    edges: list[dict] = []
    for node in wire.get("nodes", []) or []:
        if not isinstance(node, dict) or not node.get("id"):
            continue
        nid = str(node["id"])
        if nid in op_ids or nid in asset_ids:
            continue  # minimal rebuild owns op/asset/file nodes
        nodes.append(node)
    for edge in wire.get("edges", []) or []:
        if not isinstance(edge, dict):
            continue
        src, dst = str(edge.get("from", "")), str(edge.get("to", ""))
        if src in op_ids and dst in asset_ids:
            continue
        if src and dst:
            edges.append(edge)

    provenance: dict[str, str] = {}
    for node in nodes:
        nid = str(node["id"])
        files = key_files.get(nid, set())
        # file:/library: prefixed ids never occur here, but guard anyway.
        if len(files) > 1:
            provenance[nid] = "inferred"
            node["ref"] = "inferred:" + nid
            label = str(node.get("label", "") or nid)
            if not label.endswith(" (inferred)"):
                node["label"] = label + " (inferred)"
        else:
            provenance[nid] = "observed"
            node["ref"] = "observed:" + nid
    observed = sum(1 for v in provenance.values() if v == "observed")
    return {"nodes": nodes, "edges": edges, "provenance": provenance,
            "counts": {"nodes": len(nodes), "edges": len(edges),
                       "observed": observed,
                       "inferred": len(provenance) - observed}}
