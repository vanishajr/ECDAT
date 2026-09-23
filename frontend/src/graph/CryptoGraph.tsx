// Crypto Graph section: moved verbatim from App.tsx, with two
// improvements — context-aware node labels (graphLabels) and automatic
// ELK layout (graphLayout) replacing the fixed type-column positioning.
// Props, filters, inspector, and footer behavior are unchanged.

import { useEffect, useMemo, useRef, useState } from "react";
import { Controls, MarkerType, ReactFlow } from "@xyflow/react";
import { Layers, Search } from "lucide-react";
import { GraphNode } from "./GraphNode";
import { EDGE_STYLE, edgeDisplay } from "./graphEdges";
import { neighborhood } from "./graphFocus";
import { describeNode } from "./graphLabels";
import { layoutPacked } from "./graphLayout";
import { typeTone, riskPill } from "./graphModel";
import {
  GRAPH_EDGE_LIMIT,
  GRAPH_INIT_LIMIT,
  GRAPH_TYPE_ORDER,
  riskRankOf,
} from "./graphTypes";
import type { GraphEdgeDatum, GraphNodeDatum } from "./graphTypes";
import { sliceForView, filterGraphNodes } from "./graphViews";
import type { GraphViewMode } from "./graphViews";
import { buildSecurityMap, GENERIC_RULE_IDS, NODE_SIZE_PRIMARY, NODE_SIZE_SUPPORTING } from "./graphSecurityMap";
import { Card, Empty } from "./graphPrimitives";

type FullViewMode = "security" | GraphViewMode;

const graphNodeTypes = { crypto: GraphNode };

// Shared viewport fit so the button and the initial fit behave alike:
// padded, never zoomed past 1:1 (tiny graphs must not explode).
const FIT_VIEW_OPTIONS = { padding: 0.12, maxZoom: 1 };

export type JumpFn = (tab: string, rule: string | null) => void;

interface CryptoGraphProps {
  result: Record<string, unknown>;
  rel: (path: string) => string;
  jump?: JumpFn;
}

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}

function asRecord(value: unknown): Record<string, any> {
  return value && typeof value === "object"
    ? (value as Record<string, any>)
    : {};
}

export function CryptoGraph({ result, rel, jump }: CryptoGraphProps) {
  const [query, setQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("All");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [hoveredEdgeId, setHoveredEdgeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<FullViewMode>("security");
  const [rfInstance, setRfInstance] = useState<any>(null);
  const [showAll, setShowAll] = useState(false);
  const [positions, setPositions] = useState<Record<string, { x: number; y: number }>>({});
  const [layouting, setLayouting] = useState(false);
  const [announcement, setAnnouncement] = useState("");

  // Single selection path shared by mouse click and keyboard Enter/Space.
  const selectNode = (id: string | null) => {
    setSelectedId(id);
    setSelectedEdgeId(null);
  };

  const graph = asRecord(result.graph);
  const nodes: GraphNodeDatum[] = Array.isArray(graph.nodes) ? graph.nodes : [];
  const edges: GraphEdgeDatum[] = Array.isArray(graph.edges) ? graph.edges : [];
  const folded: string[] = Array.isArray(graph.folded_files)
    ? graph.folded_files
    : [];

  const typesPresent = GRAPH_TYPE_ORDER.filter((t) =>
    nodes.some((n) => n && n.type === t),
  );
  const ranked = useMemo(
    () =>
      [...nodes].sort(
        (a, b) =>
          riskRankOf(a?.risk) - riskRankOf(b?.risk) ||
          String(a?.label || "").localeCompare(String(b?.label || "")),
      ),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [nodes.length, showAll],
  );
  const capped = showAll ? ranked : ranked.slice(0, GRAPH_INIT_LIMIT);
  const q = query.trim().toLowerCase();
  const visible = capped.filter(
    (n) =>
      (typeFilter === "All" || n.type === typeFilter) &&
      (!q ||
        `${n.label || ""} ${n.id || ""} ${n.type || ""}`
          .toLowerCase()
          .includes(q)),
  );
  const visibleIds = useMemo(
    () => new Set(visible.map((n) => String(n.id))),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [visible.length, query, typeFilter, showAll, nodes.length],
  );

  // Focus scope (explore dimming) from the full visible edge set.
  const focus = useMemo(
    () => neighborhood(selectedId, edges),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [selectedId, edges.length, nodes.length],
  );
  // Edges with render-stable ids, limited to the filtered node set.
  const visibleEdges = useMemo(
    () =>
      edges
        .filter(
          (e) =>
            visibleIds.has(String(e.source)) &&
            visibleIds.has(String(e.target)),
        )
        .map((e) => ({
          id: String(e.id || `${e.source}|${e.target}`),
          source: String(e.source),
          target: String(e.target),
        })),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [visibleIds, edges.length],
  );
  // View slice: explore shows everything filtered; neighborhood narrows
  // to the selected 1-hop scope (full graph until something is picked).
  // Security Map is derived separately and never passes through here.
  const slice = useMemo(
    () =>
      sliceForView(
        [...visibleIds],
        visibleEdges,
        viewMode === "security" ? "explore" : viewMode,
        selectedId,
      ),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [visibleIds, visibleEdges, viewMode, selectedId],
  );
  // Security Map input: query/type-filtered nodes WITHOUT the Explore
  // cap — the map applies its own connected-subgraph budget instead, so
  // relationships are never severed by an arbitrary risk-ranked cutoff.
  const mapInput = useMemo(
    () => filterGraphNodes(nodes, query, typeFilter),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [nodes.length, query, typeFilter],
  );
  // Security Map: bounded, finding-oriented, connected derived graph.
  const securityMap = useMemo(
    () => (viewMode === "security" ? buildSecurityMap(mapInput, edges) : null),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [viewMode, mapInput, edges.length],
  );
  // Layout inputs depend on the active view. Security Map nodes carry
  // their render footprint so ELK reserves exactly what is drawn.
  const layoutNodesInput = useMemo(
    () =>
      securityMap
        ? securityMap.nodes.map((n) => ({
            id: n.id,
            ...(n.primary ? NODE_SIZE_PRIMARY : NODE_SIZE_SUPPORTING),
          }))
        : [...slice.nodeIds].map((id) => ({ id })),
    [securityMap, slice],
  );
  const layoutEdgesInput = useMemo(() => {
    if (securityMap) {
      return securityMap.edges.map((e) => ({ source: e.source, target: e.target }));
    }
    const byId = new Map(visibleEdges.map((e) => [e.id, e]));
    return [...slice.edgeIds]
      .map((id) => byId.get(id))
      .filter((e) => e != null)
      .map((e) => ({ source: (e as { source: string }).source, target: (e as { target: string }).target }));
  }, [securityMap, slice, visibleEdges]);
  const focusedView = viewMode === "neighborhood" && selectedId != null;
  const selectionVisible =
    selectedId == null || visibleIds.has(String(selectedId));
  const dimmed = viewMode === "explore" && selectedId != null;

  const layoutKey = useMemo(
    () =>
      layoutNodesInput.map((n) => n.id).sort().join(",") +
      "|" +
      layoutEdgesInput.map((e) => `${e.source}>${e.target}`).sort().join(","),
    [layoutNodesInput, layoutEdgesInput],
  );

  useEffect(() => {
    let live = true;
    setLayouting(true);
    // Component-packed layout keeps disconnected subgraphs compact
    // instead of spreading them across empty canvas.
    layoutPacked(layoutNodesInput, layoutEdgesInput).then((pos) => {
      if (!live) return;
      setPositions(
        Object.fromEntries(pos.map((p) => [p.id, { x: p.x, y: p.y }])),
      );
      setLayouting(false);
    });
    return () => {
      live = false;
    };
  }, [layoutKey]);

  const displayNodes = visible.filter((n) => slice.nodeIds.has(String(n.id)));
  const securityById = useMemo(
    () => new Map((securityMap?.nodes ?? []).map((n) => [n.id, n])),
    [securityMap],
  );
  // Rep-level focus scope for Security Map dimming (from derived edges).
  const securityKeep = useMemo(() => {
    const keep = new Set<string>();
    if (!securityMap || selectedId == null) return keep;
    keep.add(String(selectedId));
    for (const e of securityMap.edges) {
      if (e.source === selectedId) keep.add(e.target);
      else if (e.target === selectedId) keep.add(e.source);
    }
    return keep;
  }, [securityMap, selectedId]);
  const inSecurity = viewMode === "security" && securityMap != null;
  const flowNodes = (
    inSecurity
      ? securityMap!.nodes.map((n) => ({
          id: n.id,
          type: "crypto",
          position: positions[n.id] ?? { x: 20, y: 20 },
          data: {
            title: n.title,
            fullTitle: n.fullTitle,
            subtitle: n.subtitle,
            risk: n.risk,
            tone: n.tone,
            pill: riskPill(n.risk),
            count: n.count,
            finding: n.finding,
            primary: n.primary,
            onSelect: selectNode,
            ...(n.primary ? NODE_SIZE_PRIMARY : NODE_SIZE_SUPPORTING),
          },
          selected: n.id === selectedId,
          style: {
            opacity:
              selectedId != null && !securityKeep.has(n.id) ? 0.25 : 1,
          },
        }))
      : displayNodes.map((n, i) => {
          const id = String(n.id);
          const label = describeNode(n);
          return {
            id,
            type: "crypto",
            position: positions[id] ?? {
              x: (i % 10) * 240 + 20,
              y: Math.floor(i / 10) * 140 + 20,
            },
            data: {
              title: label.title,
              fullTitle: `${label.title}${label.subtitle ? ` — ${label.subtitle}` : ""}`,
              subtitle: label.subtitle,
              risk: String(n.risk || "info"),
              tone: typeTone(n.type),
              pill: riskPill(n.risk),
              finding: str(n.rule_id) !== "",
              onSelect: selectNode,
            },
            selected: id === selectedId,
            style: {
              opacity: dimmed && !focus.keep.has(id) ? 0.25 : 1,
            },
          };
        })
  );
  interface FlowEdge {
    id: string;
    source: string;
    target: string;
    type: "smoothstep";
    label: string | undefined;
    labelShowBg: boolean;
    style: Record<string, string | number>;
    markerEnd: { type: MarkerType; width: number; height: number; color: string };
    selected: boolean;
    interactionWidth: number;
  }
  const flowEdges: FlowEdge[] = inSecurity
    ? securityMap!.edges.map((e) => {
        const active = e.id === hoveredEdgeId || e.id === selectedEdgeId;
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          type: "smoothstep" as const,
          label:
            e.count > 1
              ? `${e.type} ×${e.count}`
              : active
                ? e.type
                : undefined,
          labelShowBg: active || e.count > 1,
          style: {
            ...EDGE_STYLE.base,
            opacity:
              selectedId != null &&
              e.source !== selectedId &&
              e.target !== selectedId
                ? 0.15
                : 1,
          },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            width: 18,
            height: 18,
            color: EDGE_STYLE.base.stroke,
          },
          selected: e.id === selectedEdgeId,
          interactionWidth: 16,
        };
      })
    : edges
    .filter((e) =>
      slice.edgeIds.has(String(e.id || `${e.source}|${e.target}`)),
    )
    .slice(0, GRAPH_EDGE_LIMIT)
    .map((e: any) => {
      const id = String(e.id || `${e.source}|${e.target}`);
      const hovered = id === hoveredEdgeId;
      const selectedE = id === selectedEdgeId;
      const display = edgeDisplay(e, hovered || selectedE);
      const base = selectedE
        ? { ...EDGE_STYLE.active }
        : hovered
          ? { ...EDGE_STYLE.hover }
          : display.lowPriority
            ? { ...EDGE_STYLE.low }
            : { ...EDGE_STYLE.base };
      const style = {
        ...base,
        opacity: dimmed && !focus.edgeKeep.has(id) ? 0.15 : 1,
      };
      return {
        id,
        source: String(e.source),
        target: String(e.target),
        type: "smoothstep" as const,
        label: display.label,
        labelShowBg: hovered || selectedE,
        style,
        markerEnd: {
          type: MarkerType.ArrowClosed,
          width: 18,
          height: 18,
          color: base.stroke,
        },
        selected: id === selectedEdgeId,
        interactionWidth: 16,
      };
    });
  const selected = nodes.find((n) => String(n?.id) === selectedId);
  const selectedMeta = asRecord(selected?.metadata);
  const byIdRaw = useMemo(
    () => new Map(nodes.map((n) => [String(n.id), n] as const)),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [result],
  );
  const selectedMapNode =
    inSecurity && selectedId != null ? securityById.get(String(selectedId)) : undefined;
  const selectedIsAggregate = selectedMapNode?.kind === "aggregate";
  // Aggregate members resolved against raw nodes for the inspector.
  const aggregateMembers = useMemo(() => {
    if (!selectedIsAggregate || !selectedMapNode) return [];
    return selectedMapNode.memberIds
      .map((id) => byIdRaw.get(id))
      .filter((n) => n != null)
      .slice(0, 12);
  }, [selectedIsAggregate, selectedMapNode]);
  const aggregateRuleIds = useMemo(() => {
    const ids = new Set<string>();
    if (selectedIsAggregate) {
      for (const m of aggregateMembers) {
        const r = str((m as GraphNodeDatum).rule_id);
        if (r) ids.add(r);
      }
    }
    return [...ids];
  }, [selectedIsAggregate, aggregateMembers]);
  const report = asRecord(result.report);
  const relatedGroups = (Array.isArray(report.finding_groups)
    ? report.finding_groups
    : []
  ).filter((g: any) =>
    selectedIsAggregate
      ? g.rule_id && aggregateRuleIds.includes(g.rule_id)
      : selected?.rule_id && g.rule_id === selected.rule_id,
  );
  const migrationByRule: Record<string, any> = {};
  for (const a of report.migration_actions || report.recommendations || []) {
    if (a && a.rule_id && !migrationByRule[a.rule_id])
      migrationByRule[a.rule_id] = a;
  }
  const relatedMigration =
    (selected?.rule_id && migrationByRule[selected.rule_id]) ||
    (selectedIsAggregate && aggregateRuleIds.length > 0
      ? migrationByRule[aggregateRuleIds.find((r) => migrationByRule[r]) ?? ""] || null
      : null);
  // Default entry point: with fresh results and nothing selected, select
  // the worst Security Map element so the inspector tells its story
  // instead of sitting empty. Runs once per result object.
  const lastResult = useRef<unknown>(null);
  useEffect(() => {
    if (lastResult.current !== result) {
      lastResult.current = result;
      if (selectedId == null && securityMap && securityMap.nodes.length > 0) {
        const top = [...securityMap.nodes].sort(
          (a, b) =>
            riskRankOf(a.risk) - riskRankOf(b.risk) ||
            Number(b.finding) - Number(a.finding) ||
            b.count - a.count ||
            a.title.localeCompare(b.title),
        )[0];
        if (top) selectNode(top.id);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [result, securityMap]);
  // Screen-reader announcements for view and selection changes.
  useEffect(() => {
    const modeLabel =
      viewMode === "security" ? "Security Map" : viewMode === "explore" ? "Explore" : "Neighborhood";
    const sel = selectedMapNode ?? selected;
    const selLabel = sel ? String((sel as { title?: unknown }).title || (sel as { label?: unknown }).label || selectedId) : null;
    setAnnouncement(
      `${modeLabel}: ${flowNodes.length} nodes shown.` +
        (selLabel ? ` Selected ${selLabel}.` : ""),
    );
  }, [viewMode, selectedId, flowNodes.length]);
  return (
    <Card className="mt-5 p-5">
      <span role="status" aria-live="polite" className="sr-only">
        {announcement}
      </span>
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="mr-auto font-medium">Crypto Graph</h3>
        <span className="text-xs text-[#74716a]">
          {nodes.length} nodes · {edges.length} relationships ·{" "}
          {folded.length} folded paths
        </span>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <div className="flex min-w-52 flex-1 items-center gap-2 rounded-full border border-[#d4d0c8] bg-white/60 px-3 py-2 focus-within:border-[#181a19]">
          <Search size={15} aria-hidden="true" />
          <input
            aria-label="Search graph by label, id, or type"
            className="w-full bg-transparent text-sm outline-none placeholder:text-[#6b675f] focus-visible:outline-none"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search graph…"
          />
        </div>
        <div className="flex flex-wrap gap-1" role="group" aria-label="Filter by node type">
          {["All", ...typesPresent].map((t) => (
            <button
              key={t}
              aria-pressed={typeFilter === t}
              className={`rounded-full px-3 py-1.5 text-xs focus-visible:outline-2 focus-visible:outline-[#181a19] ${typeFilter === t ? "bg-[#181a19] text-white" : "bg-[#e8e4dc] text-[#68645c]"}`}
              onClick={() => setTypeFilter(t)}
            >
              {t}
            </button>
          ))}
        </div>
      </div>
      <div
        className="mt-2 flex flex-wrap items-center gap-2"
        role="toolbar"
        aria-label="Crypto graph view controls"
      >
        <div
          className="flex overflow-hidden rounded-full border border-[#d4d0c8] bg-white/60"
          role="group"
          aria-label="Graph view mode"
        >
          {(
            [
              ["security", "Security Map", "Priority findings and their connections"],
              ["explore", "Explore", "Full technical inventory"],
              ["neighborhood", "Neighborhood", "Selection plus direct links"],
            ] as Array<[FullViewMode, string, string]>
          ).map(([m, label, hint]) => (
            <button
              key={m}
              aria-pressed={viewMode === m}
              title={hint}
              className={`px-3 py-1.5 text-xs ${viewMode === m ? "bg-[#181a19] text-white" : "text-[#68645c] hover:bg-[#e8e4dc]"}`}
              onClick={() => {
                // Aggregate ids exist only in the Security Map; drop them
                // when leaving so the inspector never points at a ghost.
                if (m !== "security" && selectedId?.startsWith("map:")) {
                  setSelectedId(null);
                  setSelectedEdgeId(null);
                }
                setViewMode(m);
              }}
            >
              {label}
            </button>
          ))}
        </div>
        {dimmed && (
          <span
            role="status"
            aria-live="polite"
            className="rounded-full bg-[#e8e4dc] px-3 py-1.5 text-xs text-[#292a28]"
          >
            Focused on {String(selected?.label || selectedId)} ·{" "}
            {focus.keep.size} of {visible.length} nodes in scope
          </span>
        )}
        {selectedId != null && (
          <button
            aria-label="Reset graph focus and show all filtered nodes"
            className="rounded-full border border-[#d4d0c8] bg-white/60 px-3 py-1.5 text-xs hover:bg-white"
            onClick={() => {
              setSelectedId(null);
              setSelectedEdgeId(null);
            }}
          >
            Reset focus
          </button>
        )}
        <button
          aria-label="Fit graph to view"
          className="rounded-full border border-[#d4d0c8] bg-white/60 px-3 py-1.5 text-xs hover:bg-white disabled:opacity-50"
          disabled={!rfInstance}
          onClick={() => rfInstance?.fitView(FIT_VIEW_OPTIONS)}
        >
          Fit view
        </button>
      </div>
      <p className="mt-2 text-xs text-[#74716a]" aria-hidden="true">
        {viewMode === "security" && securityMap
          ? `Priority subset — top findings and their direct connections (${securityMap.nodes.length} of ${nodes.length} nodes). Full inventory in Explore.`
          : viewMode === "explore"
            ? `Detailed inventory graph (${visible.length} of ${nodes.length} nodes). Select a node to focus it.`
            : `Selected node and its direct links. Pick any node to re-scope.`}
        {" — large card: priority finding · small card: supporting context · "}
        <span className="inline-flex items-center gap-0.5">
          <Layers size={11} aria-hidden="true" />N
        </span>
        {" = grouped repeats (click to list members) · line = uses · stronger line = depends_on"}
      </p>
      {nodes.length ? (
        <div className="mt-4 grid gap-4 lg:grid-cols-[1.6fr_1fr]">
          <div
            role="region"
            aria-label={`Crypto graph, ${viewMode} view: ${flowNodes.length} nodes, ${flowEdges.length} relationships shown`}
            className="h-[560px] overflow-hidden rounded-xl border border-[#dedbd4] bg-white/60"
          >
            <ReactFlow
              nodes={flowNodes}
              edges={flowEdges}
              nodeTypes={graphNodeTypes}
              onInit={setRfInstance}
              onNodeClick={(_, node) => selectNode(node.id)}
              onEdgeClick={(_, edge) => setSelectedEdgeId(edge.id)}
              onEdgeMouseEnter={(_, edge) => setHoveredEdgeId(edge.id)}
              onEdgeMouseLeave={() => setHoveredEdgeId(null)}
              onPaneClick={() => {
                setSelectedId(null);
                setSelectedEdgeId(null);
              }}
              fitView
              fitViewOptions={FIT_VIEW_OPTIONS}
              minZoom={0.2}
              maxZoom={2}
              nodesDraggable={false}
              proOptions={{ hideAttribution: false }}
            >
              <Controls showInteractive={false} position="top-right" />
            </ReactFlow>
          </div>
          <div className="rounded-xl border border-[#dedbd4] bg-white/45 p-4 text-sm">
            {selectedIsAggregate && selectedMapNode ? (
              <div>
                <p className="text-xs uppercase tracking-wider text-[#8b867d]">
                  {selectedMapNode.type} · {selectedMapNode.count} occurrences
                </p>
                <b className="mt-1 block break-words text-base">
                  {selectedMapNode.title}
                </b>
                <div className="mt-3 space-y-1.5 text-sm">
                  <p>
                    Worst risk:{" "}
                    <b className="capitalize">{selectedMapNode.risk}</b>
                  </p>
                  {selectedMapNode.finding && (
                    <p className="text-xs text-[#5e5d58]">
                      Linked to findings via member rule IDs
                      {aggregateRuleIds.length > 0 &&
                        `: ${aggregateRuleIds.slice(0, 3).join(", ")}${aggregateRuleIds.length > 3 ? "…" : ""}`}
                    </p>
                  )}
                  <p className="text-xs font-semibold uppercase tracking-wider text-[#8b867d]">
                    Members ({selectedMapNode.count})
                  </p>
                  <ul className="max-h-40 space-y-0.5 overflow-y-auto text-xs text-[#5e5d58]">
                    {aggregateMembers.map((m) => (
                      <li key={String((m as GraphNodeDatum).id)} className="truncate" title={String((m as GraphNodeDatum).label || (m as GraphNodeDatum).id)}>
                        {String((m as GraphNodeDatum).label || (m as GraphNodeDatum).id)}
                      </li>
                    ))}
                    {selectedMapNode.count > aggregateMembers.length && (
                      <li>… and {selectedMapNode.count - aggregateMembers.length} more.</li>
                    )}
                  </ul>
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  <button
                    className="rounded-full bg-[#181a19] px-3 py-1.5 text-xs text-white hover:bg-[#30312f]"
                    onClick={() => {
                      setSelectedId(null);
                      setSelectedEdgeId(null);
                      setQuery(String((aggregateMembers[0] as GraphNodeDatum | undefined)?.label || ""));
                      setViewMode("explore");
                    }}
                  >
                    Show members in Explore
                  </button>
                  {relatedGroups.length > 0 && jump && (
                    <button
                      className="rounded-full border border-[#d4d0c8] bg-white/60 px-3 py-1.5 text-xs hover:bg-white"
                      onClick={() => jump("Findings", relatedGroups[0].rule_id ?? null)}
                    >
                      View finding
                    </button>
                  )}
                </div>
              </div>
            ) : selected ? (
              <div>
                <p className="text-xs uppercase tracking-wider text-[#8b867d]">
                  {selected.type}
                </p>
                <b className="mt-1 block break-words text-base">
                  {selected.label}
                </b>
                <div className="mt-3 space-y-1.5 text-sm">
                  <p>
                    Risk:{" "}
                    <b className="capitalize">{selected.risk || "—"}</b>
                  </p>
                  {str(selected.rule_id) !== "" && !GENERIC_RULE_IDS.has(str(selected.rule_id)) && (
                    <p className="break-words text-xs">
                      <span className="text-[#8b867d]">Finding rule: </span>
                      <b>{str(selected.rule_id)}</b>
                    </p>
                  )}
                  {selected.confidence != null && (
                    <p>
                      Confidence: {Math.round(Number(selected.confidence) * 100)}%
                    </p>
                  )}
                  {typeof selectedMeta.location_file === "string" &&
                    selectedMeta.location_file && (
                      <p className="break-words text-xs">
                        <span className="text-[#8b867d]">Used in: </span>
                        <code>{rel(selectedMeta.location_file)}</code>
                      </p>
                    )}
                  {Object.entries(selectedMeta).filter(
                    ([k, v]) => k !== "location_file" && v != null && v !== "",
                  ).length > 0 && (
                    <details>
                      <summary className="cursor-pointer text-xs text-[#68645c]">
                        More details
                      </summary>
                      <div className="mt-1 space-y-1">
                        {Object.entries(selectedMeta)
                          .filter(([k, v]) => k !== "location_file" && v != null && v !== "")
                          .slice(0, 8)
                          .map(([k, v]) => (
                            <p key={k} className="break-words text-xs text-[#5e5d58]">
                              <span className="text-[#8b867d]">
                                {k.replaceAll("_", " ")}:{" "}
                              </span>
                              {Array.isArray(v) ? v.join(", ") : String(v)}
                            </p>
                          ))}
                      </div>
                    </details>
                  )}
                </div>
                {(relatedGroups.length > 0 || relatedMigration) && (
                  <div className="mt-4 border-t border-[#e4e0d8] pt-3">
                    <p className="text-xs font-semibold uppercase tracking-wider text-[#8b867d]">
                      Related
                    </p>
                    {relatedGroups.slice(0, 3).map((g: any) => (
                      <p
                        key={g.rule_id}
                        className="mt-1 truncate text-sm"
                        title={g.title}
                      >
                        {g.title}
                      </p>
                    ))}
                    <div className="mt-2 flex flex-wrap gap-2">
                      {relatedGroups.length > 0 && jump && (
                        <button
                          className="rounded-full border border-[#d4d0c8] bg-white/60 px-3 py-1.5 text-xs hover:bg-white"
                          onClick={() => jump("Findings", selected.rule_id ?? null)}
                        >
                          View finding
                        </button>
                      )}
                      {relatedMigration && jump && (
                        <button
                          className="rounded-full bg-[#181a19] px-3 py-1.5 text-xs text-white hover:bg-[#30312f]"
                          onClick={() => jump("Migration", selected.rule_id ?? null)}
                        >
                          View migration
                        </button>
                      )}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-sm text-[#74716a]">
                Click a node to inspect it. Drag to pan, scroll to zoom.
                {layouting ? " Arranging graph…" : ""}
              </p>
            )}
          </div>
        </div>
      ) : (
        <Empty label="No graph nodes available." />
      )}
      <div className="mt-3 flex flex-wrap items-center gap-3 text-xs text-[#74716a]">
        {inSecurity && securityMap && (
          <span className="rounded-full bg-[#181a19] px-3 py-1.5 text-white">
            Security Map: {securityMap.nodes.length} shown ·{" "}
            {securityMap.hiddenNodes} more in Explore ·{" "}
            <button
              className="underline"
              onClick={() => {
                setSelectedId(null);
                setSelectedEdgeId(null);
                setShowAll(true);
                setViewMode("explore");
              }}
            >
              Open full graph
            </button>
          </span>
        )}
        {focusedView && (
          <span className="rounded-full bg-[#181a19] px-3 py-1.5 text-white">
            Neighborhood: {slice.nodeIds.size} of {visible.length} nodes ·{" "}
            {slice.hiddenNodes} hidden ·{" "}
            <button
              className="underline"
              onClick={() => setViewMode("explore")}
            >
              Back to Explore
            </button>
          </span>
        )}
        {selectedId != null && !selectionVisible && (
          <span className="rounded-full bg-[#e8e4dc] px-3 py-1.5 text-[#292a28]">
            Selected node is outside the current search or type filter ·{" "}
            <button
              className="underline"
              onClick={() => {
                setQuery("");
                setTypeFilter("All");
              }}
            >
              Clear filters
            </button>
          </span>
        )}
        {!showAll && nodes.length > GRAPH_INIT_LIMIT ? (
          <button
            className="rounded-full bg-[#e8e4dc] px-3 py-1.5 text-[#292a28] hover:bg-[#dedbd4]"
            onClick={() => setShowAll(true)}
          >
            Show all {nodes.length} nodes (currently top {GRAPH_INIT_LIMIT} by
            risk)
          </button>
        ) : (
          <span>
            Showing {visible.length} of {nodes.length} nodes
            {showAll && nodes.length > GRAPH_INIT_LIMIT ? " (all)" : ""}
          </span>
        )}
        {folded.length > 0 && (
          <details>
            <summary className="cursor-pointer">
              {folded.length} folded file paths
            </summary>
            <ul className="mt-1 max-h-32 list-disc space-y-0.5 overflow-y-auto pl-5">
              {folded.slice(0, 50).map((f) => (
                <li key={f} className="break-all">
                  {rel(f)}
                </li>
              ))}
              {folded.length > 50 && <li>… and {folded.length - 50} more.</li>}
            </ul>
          </details>
        )}
      </div>
    </Card>
  );
}
