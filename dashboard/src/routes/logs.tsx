import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import {
  Search, Filter, Download, Terminal, ListTree, ChevronDown, ChevronRight,
  Clock,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { useWebSocketContext } from "@/components/websocket-provider";

export const Route = createFileRoute("/logs")({
  head: () => ({
    meta: [
      { title: "Logs — AETHER-PQ" },
      { name: "description", content: "Searchable, filterable protocol logs across the AETHER-PQ platform with timeline and raw views." },
    ],
  }),
  component: LogsPage,
});

type Severity = "debug" | "info" | "notice" | "warning" | "error" | "critical";
type Protocol = "MAVLink" | "TLS" | "TreeKEM" | "OCSP" | "MLKEM" | "MLDSA" | "SSH" | "gRPC";
type Subsystem = "GCS" | "CA" | "ACPE" | "TreeKEM" | "Fleet" | "Network" | "ns-3" | "Auth";

type LogEntry = {
  ts: string;
  epochMs: number;
  severity: Severity;
  protocol: Protocol;
  subsystem: Subsystem;
  node: string;
  message: string;
  ctx?: Record<string, string | number>;
};



const SEVERITIES: Severity[] = ["debug", "info", "notice", "warning", "error", "critical"];
const PROTOCOLS: Protocol[] = ["MAVLink", "TLS", "TreeKEM", "OCSP", "MLKEM", "MLDSA", "SSH", "gRPC"];
const SUBSYSTEMS: Subsystem[] = ["GCS", "CA", "ACPE", "TreeKEM", "Fleet", "Network", "ns-3", "Auth"];

function sevTone(s: Severity) {
  return s === "critical" ? "critical" : s === "error" ? "critical" : s === "warning" ? "warning" : s === "notice" ? "info" : "neutral";
}

function Pill({ tone, children }: { tone: "success" | "warning" | "critical" | "neutral" | "info"; children: React.ReactNode }) {
  const cls = {
    success: "bg-success-muted text-success",
    warning: "bg-warning-muted text-warning",
    critical: "bg-critical-muted text-critical",
    neutral: "bg-surface-2 text-muted-foreground",
    info: "bg-primary-muted text-primary",
  }[tone];
  return <span className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-[10.5px] font-medium ${cls}`}>{children}</span>;
}

function LogsPage() {
  const { data, status } = useWebSocketContext();

  if (status !== "open" || !data) {
    return (
      <AppShell
        eyebrow="Diagnostics · Logs"
        title="Protocol Logs"
        breadcrumbs={[{ label: "Diagnostics", to: "/" }, { label: "Logs" }]}
      >
        <div className="flex h-[400px] flex-col items-center justify-center rounded-lg border border-border bg-card p-8 text-center shadow-xs">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
          <h2 className="mt-4 text-[16px] font-semibold text-foreground">Waiting for backend connection...</h2>
          <p className="mt-2 text-[13px] text-muted-foreground">The Swarmlink control server is offline or disconnected.</p>
        </div>
      </AppShell>
    );
  }

  const activeActivity = data.recentActivity || [];

  const exportLogsTxt = () => {
    const textContent = liveLogs.map(l => `[${l.ts}] [${l.severity.toUpperCase()}] [Subsystem=${l.subsystem}] [Protocol=${l.protocol}] [Source=${l.node}] ${l.message}`).join("\n");
    const blob = new Blob([textContent], { type: "text/plain;charset=utf-8" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `aether_pq_logs_${new Date().toISOString().slice(0,10)}.txt`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const liveLogs: LogEntry[] = useMemo(() => {
    const list = activeActivity.map((act: any, idx: number) => {
      let subsystem: Subsystem = "Fleet";
      let protocol: Protocol = "MAVLink";
      if (act.actor === "TreeKEM") { subsystem = "TreeKEM"; protocol = "TreeKEM"; }
      else if (act.actor === "ACPE") { subsystem = "ACPE"; protocol = "TLS"; }
      else if (act.actor === "CA") { subsystem = "CA"; protocol = "OCSP"; }
      else if (act.actor === "LTE" || act.actor === "MESH") { subsystem = "Network"; protocol = "TLS"; }
      else if (act.actor === "GCS") { subsystem = "GCS"; protocol = "MAVLink"; }

      return {
        ts: act.ts,
        epochMs: Date.now() - idx * 5000,
        severity: (act.severity === "success" ? "info" : act.severity) as Severity,
        protocol,
        subsystem,
        node: act.actor.toLowerCase(),
        message: act.message,
        ctx: {}
      };
    });
    return list;
  }, [activeActivity]);

  const [q, setQ] = useState("");
  const [sev, setSev] = useState<Set<Severity>>(new Set(["notice", "warning", "error", "critical", "info"]));
  const [proto, setProto] = useState<"ALL" | Protocol>("ALL");
  const [sub, setSub] = useState<"ALL" | Subsystem>("ALL");
  const [node, setNode] = useState("");
  const [range, setRange] = useState<"5m" | "15m" | "1h" | "6h" | "24h">("15m");
  const [view, setView] = useState<"timeline" | "raw">("timeline");
  const [expanded, setExpanded] = useState<number | null>(null);

  const filtered = useMemo(() => {
    const now = Date.now();
    const spans: Record<string, number> = { "5m": 300, "15m": 900, "1h": 3600, "6h": 21600, "24h": 86400 };
    // logs are synthetic relative to a fixed base; treat range as "top-N"
    const capByRange: Record<string, number> = { "5m": 40, "15m": 90, "1h": 120, "6h": 120, "24h": 120 };
    const cap = capByRange[range];
    return liveLogs.slice(0, cap).filter((l) => {
      if (!sev.has(l.severity)) return false;
      if (proto !== "ALL" && l.protocol !== proto) return false;
      if (sub !== "ALL" && l.subsystem !== sub) return false;
      if (node.trim() && !l.node.toLowerCase().includes(node.toLowerCase())) return false;
      if (q.trim()) {
        const s = q.toLowerCase();
        if (!l.message.toLowerCase().includes(s) && !JSON.stringify(l.ctx ?? {}).toLowerCase().includes(s)) return false;
      }
      return true;
    });
  }, [q, sev, proto, sub, node, range]);

  const counts = useMemo(() => {
    const c: Record<Severity, number> = { debug: 0, info: 0, notice: 0, warning: 0, error: 0, critical: 0 };
    filtered.forEach((l) => c[l.severity]++);
    return c;
  }, [filtered]);

  const toggleSev = (s: Severity) => {
    setSev((prev) => { const n = new Set(prev); n.has(s) ? n.delete(s) : n.add(s); return n; });
  };

  return (
    <AppShell
      eyebrow="Diagnostics · Logs"
      title="Protocol Logs"
      breadcrumbs={[{ label: "Diagnostics", to: "/" }, { label: "Logs" }]}
      actions={
        <>
          <div className="flex items-center gap-1 rounded-md border border-border bg-background p-0.5">
            <button onClick={() => setView("timeline")} className={`inline-flex items-center gap-1.5 rounded px-2.5 py-1 text-[11.5px] font-medium ${view === "timeline" ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-surface-2"}`}>
              <ListTree className="h-3.5 w-3.5" /> Timeline
            </button>
            <button onClick={() => setView("raw")} className={`inline-flex items-center gap-1.5 rounded px-2.5 py-1 text-[11.5px] font-medium ${view === "raw" ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-surface-2"}`}>
              <Terminal className="h-3.5 w-3.5" /> Raw
            </button>
          </div>
          <button 
            onClick={exportLogsTxt}
            className="inline-flex items-center gap-1.5 rounded-md border border-border bg-background px-3 py-1.5 text-[12.5px] font-medium hover:bg-surface-2 cursor-pointer focus:outline-none"
          >
            <Download className="h-3.5 w-3.5" /> Export
          </button>
        </>
      }
    >
      {/* Severity strip */}
      <div className="mb-3 grid grid-cols-2 gap-2 md:grid-cols-6">
        {SEVERITIES.map((s) => {
          const active = sev.has(s);
          const tone = sevTone(s);
          return (
            <button
              key={s}
              onClick={() => toggleSev(s)}
              className={`rounded-lg border p-3 text-left transition-colors ${active ? "border-border bg-card shadow-xs" : "border-border bg-surface-2 opacity-60"}`}
            >
              <div className="flex items-center justify-between">
                <span className={`text-[11px] font-semibold uppercase tracking-wider ${
                  tone === "critical" ? "text-critical" : tone === "warning" ? "text-warning" : tone === "info" ? "text-primary" : "text-muted-foreground"
                }`}>{s}</span>
                <span className={`h-1.5 w-1.5 rounded-full`} style={{ background:
                  tone === "critical" ? "var(--color-critical)" :
                  tone === "warning" ? "var(--color-warning)" :
                  tone === "info" ? "var(--color-primary)" :
                  "var(--color-muted-foreground)"
                }} />
              </div>
              <div className="mt-1 text-tabular text-[18px] font-semibold text-foreground">{counts[s]}</div>
            </button>
          );
        })}
      </div>

      {/* Filter bar */}
      <div className="mb-3 flex flex-wrap items-center gap-2 rounded-lg border border-border bg-card px-3 py-2 shadow-xs">
        <div className="relative min-w-[240px] flex-1 max-w-lg">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search messages, context, key=value…"
            className="h-8 w-full rounded-md border border-border bg-background pl-8 pr-3 text-[13px] font-mono outline-none placeholder:text-muted-foreground placeholder:font-sans focus:border-primary focus:ring-2 focus:ring-ring"
          />
        </div>
        <div className="flex items-center gap-1.5">
          <Filter className="h-3.5 w-3.5 text-muted-foreground" />
          <select value={proto} onChange={(e) => setProto(e.target.value as any)} className="h-8 rounded-md border border-border bg-background px-2 text-[12.5px] outline-none focus:border-primary">
            <option value="ALL">All protocols</option>
            {PROTOCOLS.map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
          <select value={sub} onChange={(e) => setSub(e.target.value as any)} className="h-8 rounded-md border border-border bg-background px-2 text-[12.5px] outline-none focus:border-primary">
            <option value="ALL">All subsystems</option>
            {SUBSYSTEMS.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <input
            value={node}
            onChange={(e) => setNode(e.target.value)}
            placeholder="Node…"
            className="h-8 w-32 rounded-md border border-border bg-background px-2 text-[12.5px] font-mono outline-none placeholder:font-sans placeholder:text-muted-foreground focus:border-primary"
          />
        </div>
        <div className="ml-auto flex items-center gap-1 rounded-md border border-border bg-background p-0.5">
          <Clock className="ml-1 h-3 w-3 text-muted-foreground" />
          {(["5m", "15m", "1h", "6h", "24h"] as const).map((r) => (
            <button key={r} onClick={() => setRange(r)} className={`rounded px-2 py-1 text-[11px] font-medium ${range === r ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-surface-2"}`}>
              {r}
            </button>
          ))}
        </div>
      </div>

      <div className="mb-2 flex items-center justify-between text-[11.5px] text-muted-foreground">
        <span>Showing <span className="text-tabular font-semibold text-foreground">{filtered.length}</span> of {liveLogs.length} entries</span>
        <span>Live tail · <span className="text-tabular text-foreground">{liveLogs[0]?.ts || "—"}</span></span>
      </div>

      {/* Body */}
      {view === "timeline" ? (
        <div className="overflow-hidden rounded-lg border border-border bg-card shadow-xs">
          <ul>
            {filtered.map((l, i) => {
              const tone = sevTone(l.severity);
              const open = expanded === i;
              return (
                <li key={i} className="border-b border-border last:border-b-0">
                  <button
                    onClick={() => setExpanded(open ? null : i)}
                    className="grid w-full grid-cols-[150px_90px_120px_120px_1fr_28px] items-center gap-3 px-4 py-2.5 text-left hover:bg-surface"
                  >
                    <span className="text-tabular text-[11.5px] text-muted-foreground">{l.ts}</span>
                    <Pill tone={tone as any}>{l.severity.toUpperCase()}</Pill>
                    <span className="text-tabular text-[11.5px] text-foreground">{l.protocol}</span>
                    <span className="text-tabular text-[11.5px] text-muted-foreground">
                      {l.subsystem} · <span className="text-foreground">{l.node}</span>
                    </span>
                    <span className="truncate text-[13px] text-foreground">{l.message}</span>
                    {open ? <ChevronDown className="h-4 w-4 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 text-muted-foreground" />}
                  </button>
                  {open && (
                    <div className="border-t border-border bg-surface px-4 py-3">
                      <div className="mb-2 text-overline">Context</div>
                      <div className="grid grid-cols-2 gap-x-6 gap-y-1 md:grid-cols-4">
                        {Object.entries(l.ctx ?? {}).map(([k, v]) => (
                          <div key={k} className="flex justify-between border-b border-border py-1 text-[12px]">
                            <span className="text-muted-foreground">{k}</span>
                            <span className="text-tabular font-medium text-foreground">{String(v)}</span>
                          </div>
                        ))}
                      </div>
                      <pre className="mt-3 overflow-x-auto rounded-md border border-border bg-background p-3 text-[11.5px] font-mono text-foreground">
{JSON.stringify({ ts: l.ts, severity: l.severity, protocol: l.protocol, subsystem: l.subsystem, node: l.node, message: l.message, ctx: l.ctx ?? {} }, null, 2)}
                      </pre>
                    </div>
                  )}
                </li>
              );
            })}
            {filtered.length === 0 && (
              <li className="px-4 py-10 text-center text-[13px] text-muted-foreground">
                No log entries match the current filters.
              </li>
            )}
          </ul>
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-border bg-background shadow-xs">
          <pre className="max-h-[70vh] overflow-auto p-4 text-[12px] font-mono leading-relaxed text-foreground">
{filtered.map((l) => {
  const kv = l.ctx ? " " + Object.entries(l.ctx).map(([k, v]) => `${k}=${typeof v === "string" ? `"${v}"` : v}`).join(" ") : "";
  return `${l.ts} [${l.severity.toUpperCase().padEnd(8)}] ${l.protocol.padEnd(8)} ${l.subsystem.padEnd(8)} ${l.node.padEnd(10)} ${l.message}${kv}`;
}).join("\n")}
          </pre>
        </div>
      )}
    </AppShell>
  );
}
