import React from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import {
  Search, ArrowUpDown, Download, Filter, MoreHorizontal, Plane,
  Battery, Signal, ChevronDown, ChevronRight, X, Copy, Terminal,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { type UAV } from "@/lib/types";

export const Route = createFileRoute("/fleet")({
  head: () => ({
    meta: [
      { title: "UAV Fleet — AETHER-PQ" },
      { name: "description", content: "Tabular roster of the entire UAV fleet with search, filter, sort, grouping, and quick actions." },
    ],
  }),
  component: FleetPage,
});

type SortKey = "id" | "battery" | "latency" | "rssi" | "cpu" | "status";

const statusTone: Record<UAV["status"], "success" | "warning" | "critical" | "neutral"> = {
  nominal: "success",
  degraded: "warning",
  critical: "critical",
  offline: "neutral",
  maintenance: "neutral",
};

function StatusPill({ tone, children }: { tone: "success" | "warning" | "critical" | "neutral" | "info"; children: React.ReactNode }) {
  const cls = {
    success: "bg-success-muted text-success",
    warning: "bg-warning-muted text-warning",
    critical: "bg-critical-muted text-critical",
    neutral: "bg-surface-2 text-muted-foreground",
    info: "bg-primary-muted text-primary",
  }[tone];
  return <span className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-[11px] font-medium ${cls}`}>{children}</span>;
}

function StatCard({ label, value, sub, tone }: { label: string; value: string | number; sub?: string; tone?: "success" | "warning" | "critical" | "primary" }) {
  return (
    <div className="rounded-lg border border-border bg-card p-4 shadow-xs">
      <div className="text-overline">{label}</div>
      <div className="mt-2 flex items-baseline gap-2">
        <span className={`text-tabular text-[24px] font-semibold leading-none tracking-tight ${
          tone === "critical" ? "text-critical" : tone === "warning" ? "text-warning" : tone === "success" ? "text-success" : "text-foreground"
        }`}>{value}</span>
        {sub && <span className="text-[11.5px] text-muted-foreground">{sub}</span>}
      </div>
    </div>
  );
}

import { useWebSocketContext } from "@/components/websocket-provider";

function FleetPage() {
  const { data, status, sendCommand } = useWebSocketContext();
  const [showExternalNodeModal, setShowExternalNodeModal] = useState(false);
  const [copied, setCopied] = useState(false);

  const [q, setQ] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | UAV["status"]>("all");
  const [groupBy, setGroupBy] = useState<"none" | "group" | "status" | "policyMode">("group");
  const [sortKey, setSortKey] = useState<SortKey>("id");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());
  const [activeMenu, setActiveMenu] = useState<string | null>(null);

  const activeFleet = data?.fleet || [];
  const exportFleetCsv = () => {
    const headers = ["ID", "Callsign", "Mission", "Status", "Battery", "RSSI", "Latency", "CPU", "Operating Mode", "Crypto Profile", "Policy Mode"];
    const rows = activeFleet.map(u => [
      u.id,
      u.callsign,
      `"${u.mission.replace(/"/g, '""')}"`,
      u.status,
      `${u.battery}%`,
      `${u.rssi} dBm`,
      `${u.latency} ms`,
      `${u.cpu}%`,
      u.operatingMode,
      u.cryptoProfile,
      u.policyMode
    ]);
    const csvContent = "data:text/csv;charset=utf-8," 
      + [headers.join(","), ...rows.map(e => e.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `aether_pq_fleet_${new Date().toISOString().slice(0,10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };
  const filtered = useMemo(() => {
    let list = [...activeFleet];
    if (statusFilter !== "all") list = list.filter((u) => u.status === statusFilter);
    if (q.trim()) {
      const s = q.toLowerCase();
      list = list.filter((u) =>
        u.id.toLowerCase().includes(s) || u.callsign.toLowerCase().includes(s) || u.mission.toLowerCase().includes(s)
      );
    }
    list.sort((a: any, b: any) => {
      const va = a[sortKey]; const vb = b[sortKey];
      if (va === vb) return 0;
      const cmp = va > vb ? 1 : -1;
      return sortDir === "asc" ? cmp : -cmp;
    });
    return list;
  }, [q, statusFilter, sortKey, sortDir, activeFleet]);

  const grouped = useMemo(() => {
    if (groupBy === "none") return [{ key: "All UAVs", items: filtered }];
    const map = new Map<string, UAV[]>();
    for (const u of filtered) {
      const k = groupBy === "group" ? `Group ${u.fleetGroup}` : groupBy === "status" ? u.status.toUpperCase() : u.policyMode;
      const arr = map.get(k) ?? []; arr.push(u); map.set(k, arr);
    }
    return Array.from(map.entries()).map(([key, items]) => ({ key, items }));
  }, [filtered, groupBy]);

  if (status !== "open" || !data) {
    return (
      <AppShell
        eyebrow="Infrastructure · Fleet"
        title="UAV Fleet"
        breadcrumbs={[{ label: "Infrastructure", to: "/" }, { label: "UAV Fleet" }]}
      >
        <div className="flex h-[400px] flex-col items-center justify-center rounded-lg border border-border bg-card p-8 text-center shadow-xs">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
          <h2 className="mt-4 text-[16px] font-semibold text-foreground">Waiting for backend connection...</h2>
          <p className="mt-2 text-[13px] text-muted-foreground">The Swarmlink control server is offline or disconnected.</p>
        </div>
      </AppShell>
    );
  }

  const toggleSort = (k: SortKey) => {
    if (sortKey === k) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortKey(k); setSortDir("asc"); }
  };

  const toggleSel = (id: string) => {
    setSelected((s) => {
      const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n;
    });
  };

  const toggleGroup = (k: string) => {
    setCollapsedGroups((s) => { const n = new Set(s); n.has(k) ? n.delete(k) : n.add(k); return n; });
  };

  const nominal = activeFleet.filter((u) => u.status === "nominal").length;
  const critical = activeFleet.filter((u) => u.status === "critical").length;
  const degraded = activeFleet.filter((u) => u.status === "degraded").length;
  const avgBattery = activeFleet.length > 0 ? Math.round(activeFleet.reduce((a, u) => a + u.battery, 0) / activeFleet.length) : 0;

  return (
    <AppShell
      eyebrow="Infrastructure · Fleet"
      title="UAV Fleet"
      breadcrumbs={[{ label: "Infrastructure", to: "/" }, { label: "UAV Fleet" }]}
      actions={
        <>
          <button 
            onClick={exportFleetCsv}
            className="inline-flex items-center gap-1.5 rounded-md border border-border bg-background px-3 py-1.5 text-[12.5px] font-medium hover:bg-surface-2 cursor-pointer focus:outline-none"
          >
            <Download className="h-3.5 w-3.5" /> Export CSV
          </button>
          <button 
            onClick={() => setShowExternalNodeModal(true)}
            className="inline-flex items-center gap-1.5 rounded-md border border-border bg-background px-3 py-1.5 text-[12.5px] font-medium hover:bg-surface-2 cursor-pointer focus:outline-none"
          >
            <Terminal className="h-3.5 w-3.5 text-muted-foreground" /> Connect External Node
          </button>
          <button 
            onClick={() => sendCommand("register-uav")}
            className="rounded-md bg-primary px-3 py-1.5 text-[12.5px] font-medium text-primary-foreground hover:opacity-90 cursor-pointer"
          >
            Register Local UAV
          </button>
        </>
      }
    >
      {/* Stats */}
      <div className="mb-5 grid grid-cols-2 gap-4 md:grid-cols-5">
        <StatCard label="Total UAVs" value={activeFleet.length} sub="registered" />
        <StatCard label="Nominal" value={nominal} sub="operational" tone="success" />
        <StatCard label="Degraded" value={degraded} sub="attention" tone="warning" />
        <StatCard label="Critical" value={critical} sub="intervention" tone="critical" />
        <StatCard label="Avg Battery" value={`${avgBattery}%`} sub="fleet-wide" tone="primary" />
      </div>

      {/* Controls */}
      <div className="mb-3 flex flex-wrap items-center gap-2 rounded-lg border border-border bg-card px-3 py-2 shadow-xs">
        <div className="relative flex-1 min-w-[220px] max-w-md">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search by ID, callsign, or mission…"
            className="h-8 w-full rounded-md border border-border bg-background pl-8 pr-3 text-[13px] outline-none placeholder:text-muted-foreground focus:border-primary focus:ring-2 focus:ring-ring"
          />
        </div>
        <div className="flex items-center gap-1.5">
          <Filter className="h-3.5 w-3.5 text-muted-foreground" />
          <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value as any)} className="h-8 rounded-md border border-border bg-background px-2 text-[12.5px] outline-none focus:border-primary">
            <option value="all">All statuses</option>
            <option value="nominal">Nominal</option>
            <option value="degraded">Degraded</option>
            <option value="critical">Critical</option>
            <option value="offline">Offline</option>
            <option value="maintenance">Maintenance</option>
          </select>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-[11.5px] text-muted-foreground">Group by</span>
          <select value={groupBy} onChange={(e) => setGroupBy(e.target.value as any)} className="h-8 rounded-md border border-border bg-background px-2 text-[12.5px] outline-none focus:border-primary">
            <option value="none">None</option>
            <option value="group">Fleet Group</option>
            <option value="status">Status</option>
            <option value="policyMode">Policy Mode</option>
          </select>
        </div>
        <div className="ml-auto flex items-center gap-2">
          {selected.size > 0 && (
            <>
              <span className="text-tabular text-[11.5px] text-muted-foreground">{selected.size} selected</span>
              <button disabled className="rounded-md border border-border bg-background px-2.5 py-1 text-[11.5px] opacity-50 cursor-not-allowed" title="Feature not implemented by backend.">Rekey</button>
              <button disabled className="rounded-md border border-border bg-background px-2.5 py-1 text-[11.5px] opacity-50 cursor-not-allowed" title="Feature not implemented by backend.">Rotate Cert</button>
              <button disabled className="rounded-md border border-critical/40 bg-critical-muted px-2.5 py-1 text-[11.5px] text-critical opacity-50 cursor-not-allowed" title="Feature not implemented by backend.">Quarantine</button>
            </>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="overflow-hidden rounded-lg border border-border bg-card shadow-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead className="border-b border-border bg-surface">
              <tr className="text-left text-[11px] uppercase tracking-wider text-muted-foreground">
                <th className="w-9 px-3 py-2.5"></th>
                <Th onClick={() => toggleSort("id")} active={sortKey === "id"} dir={sortDir}>UAV</Th>
                <th className="px-3 py-2.5 font-medium">Mission</th>
                <Th onClick={() => toggleSort("status")} active={sortKey === "status"} dir={sortDir}>Status</Th>
                <Th onClick={() => toggleSort("battery")} active={sortKey === "battery"} dir={sortDir} align="right">Battery</Th>
                <Th onClick={() => toggleSort("rssi")} active={sortKey === "rssi"} dir={sortDir} align="right">RSSI</Th>
                <Th onClick={() => toggleSort("latency")} active={sortKey === "latency"} dir={sortDir} align="right">Latency</Th>
                <Th onClick={() => toggleSort("cpu")} active={sortKey === "cpu"} dir={sortDir} align="right">CPU</Th>
                <th className="px-3 py-2.5 font-medium">Mode</th>
                <th className="px-3 py-2.5 font-medium">Crypto Profile</th>
                <th className="px-3 py-2.5 font-medium">Policy</th>
                <th className="w-10 px-3 py-2.5"></th>
              </tr>
            </thead>
            <tbody>
              {grouped.map((g) => {
                const collapsed = collapsedGroups.has(g.key);
                return (
                  <React.Fragment key={g.key}>
                    {groupBy !== "none" && (
                      <tr key={g.key + "-h"} className="bg-surface-2/60 border-b border-border">
                        <td colSpan={12} className="px-3 py-2">
                          <button onClick={() => toggleGroup(g.key)} className="flex w-full items-center gap-2 text-[11.5px] font-medium uppercase tracking-wider text-muted-foreground hover:text-foreground">
                            {collapsed ? <ChevronRight className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                            <span>{g.key}</span>
                            <span className="text-tabular text-[10.5px] normal-case tracking-normal text-muted-foreground">{g.items.length} UAV{g.items.length !== 1 ? "s" : ""}</span>
                          </button>
                        </td>
                      </tr>
                    )}
                    {!collapsed && g.items.map((u, i) => (
                      <tr key={u.id} className={`border-b border-border last:border-b-0 hover:bg-surface ${i % 2 === 1 ? "bg-surface/40" : ""}`}>
                        <td className="px-3 py-2.5">
                          <input type="checkbox" checked={selected.has(u.id)} onChange={() => toggleSel(u.id)} className="h-3.5 w-3.5 rounded border-border accent-primary" />
                        </td>
                        <td className="px-3 py-2.5">
                          <div className="flex items-center gap-2">
                            <div className="flex h-6 w-6 items-center justify-center rounded bg-surface-2">
                              <Plane className="h-3 w-3 text-muted-foreground" />
                            </div>
                            <div>
                              <div className="text-tabular font-medium text-foreground">{u.id}</div>
                              <div className="text-[11px] text-muted-foreground">{u.callsign}</div>
                            </div>
                          </div>
                        </td>
                        <td className="px-3 py-2.5 text-[12.5px] text-muted-foreground max-w-[220px] truncate">{u.mission}</td>
                        <td className="px-3 py-2.5"><StatusPill tone={statusTone[u.status]}>{u.status.toUpperCase()}</StatusPill></td>
                        <td className="px-3 py-2.5 text-right">
                          <div className="inline-flex items-center gap-2">
                            <div className="h-1.5 w-16 overflow-hidden rounded-full bg-surface-2">
                              <div className="h-full rounded-full" style={{ width: `${u.battery}%`, background: u.battery < 20 ? "var(--color-critical)" : u.battery < 40 ? "var(--color-warning)" : "var(--color-success)" }} />
                            </div>
                            <span className="text-tabular text-[12px] w-9 text-right">{u.battery}%</span>
                          </div>
                        </td>
                        <td className="px-3 py-2.5 text-right text-tabular text-[12.5px]">{u.rssi} <span className="text-[10.5px] text-muted-foreground">dBm</span></td>
                        <td className="px-3 py-2.5 text-right text-tabular text-[12.5px]">
                          <span className={u.latency > 200 ? "text-critical" : u.latency > 150 ? "text-warning" : "text-foreground"}>{u.latency}</span>
                          <span className="text-[10.5px] text-muted-foreground"> ms</span>
                        </td>
                        <td className="px-3 py-2.5 text-right text-tabular text-[12.5px]">
                          <span className={u.cpu > 80 ? "text-critical" : u.cpu > 60 ? "text-warning" : "text-foreground"}>{u.cpu}%</span>
                        </td>
                        <td className="px-3 py-2.5 text-tabular text-[11.5px] text-muted-foreground">{u.operatingMode}</td>
                        <td className="px-3 py-2.5 text-tabular text-[11.5px]">{u.cryptoProfile}</td>
                        <td className="px-3 py-2.5"><StatusPill tone="info">{u.policyMode}</StatusPill></td>
                        <td className="px-3 py-2.5">
                          <div className="relative">
                            <button 
                              onClick={(e) => {
                                e.stopPropagation();
                                setActiveMenu(activeMenu === u.id ? null : u.id);
                              }}
                              className="flex h-7 w-7 items-center justify-center rounded-md hover:bg-surface-2 cursor-pointer focus:outline-none"
                            >
                              <MoreHorizontal className="h-4 w-4 text-muted-foreground" />
                            </button>
                            {activeMenu === u.id && (
                              <>
                                <div className="fixed inset-0 z-40" onClick={() => setActiveMenu(null)} />
                                <div className="absolute right-0 mt-1 w-36 rounded-md border border-border bg-card p-1 shadow-md z-50">
                                  <button
                                    onClick={() => {
                                      sendCommand("node-shutdown", { id: u.id });
                                      setActiveMenu(null);
                                    }}
                                    className="w-full text-left rounded-sm px-2 py-1.5 text-[12px] font-semibold text-destructive hover:bg-destructive/10 cursor-pointer focus:outline-none"
                                  >
                                    Shutdown Process
                                  </button>
                                </div>
                              </>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
        <div className="flex items-center justify-between border-t border-border bg-surface px-4 py-2.5 text-[11.5px] text-muted-foreground">
          <div>Showing <span className="text-tabular font-medium text-foreground">{filtered.length}</span> of {activeFleet.length} UAVs</div>
          <div className="flex items-center gap-2">
            <button disabled className="rounded border border-border bg-background px-2 py-0.5 opacity-50 cursor-not-allowed" title="Only one page available.">‹ Prev</button>
            <span className="text-tabular">Page 1 / 1</span>
            <button disabled className="rounded border border-border bg-background px-2 py-0.5 opacity-50 cursor-not-allowed" title="Only one page available.">Next ›</button>
          </div>
        </div>
      </div>

      {/* External Node Registration Modal */}
      {showExternalNodeModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true">
          <div className="absolute inset-0 bg-overlay backdrop-blur-xs" onClick={() => setShowExternalNodeModal(false)} />
          <div className="relative w-full max-w-lg rounded-lg border border-border bg-card p-6 shadow-md animate-fade-in-scale">
            <div className="flex items-center justify-between border-b border-border/80 pb-3">
              <div className="flex items-center gap-2">
                <Terminal className="h-4 w-4 text-primary" />
                <h3 className="font-semibold text-foreground text-[14.5px]">Register External Hardware Node</h3>
              </div>
              <button
                onClick={() => setShowExternalNodeModal(false)}
                className="rounded-md p-1 hover:bg-surface-2 text-muted-foreground hover:text-foreground focus:outline-none"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="mt-4 space-y-4 text-[12.5px] leading-relaxed text-muted-foreground">
              <p>
                To onboard a physical embedded drone board (e.g. ARMv7 Cortex-A9) onto the post-quantum swarm local network:
              </p>
              
              <ol className="list-decimal pl-5 space-y-2">
                <li>Compile the target executable on your development host or directly on the embedded board:
                  <pre className="mt-1 bg-surface-2 p-2 rounded-md font-mono text-[11px] text-foreground border border-border/60">make uav_pqc_uav_node</pre>
                </li>
                <li>Transfer or deploy the compiled binary to the physical drone filesystem.</li>
                <li>Execute the registration handshake command by replacing <code className="font-mono text-primary bg-primary/10 px-1 rounded">&lt;drone_ip&gt;</code> with the board's IP address:</li>
              </ol>

              {/* Dynamic Command Code Block */}
              <div className="relative rounded-md border border-border bg-surface-2 p-3 font-mono text-[11px] text-foreground overflow-x-auto">
                <button
                  type="button"
                  onClick={() => {
                    const cmd = `./uav_pqc_uav_node --id ${activeFleet.length + 1} --ip <drone_ip> --port ${28002 + activeFleet.length + 1} --gcs-ip ${typeof window !== "undefined" ? window.location.hostname : "127.0.0.1"} --gcs-port 28001 --ca-ip ${typeof window !== "undefined" ? window.location.hostname : "127.0.0.1"} --ca-port 28000`;
                    navigator.clipboard.writeText(cmd);
                    setCopied(true);
                    setTimeout(() => setCopied(false), 2000);
                  }}
                  className="absolute right-2.5 top-2.5 rounded-md border border-border bg-card px-2 py-1 text-[10px] font-semibold hover:bg-surface-2 flex items-center gap-1 cursor-pointer focus:outline-none"
                >
                  <Copy className="h-3 w-3" />
                  {copied ? "Copied!" : "Copy"}
                </button>
                <pre className="pr-12 whitespace-pre-wrap select-all">
{`./uav_pqc_uav_node \\
  --id ${activeFleet.length + 1} \\
  --ip <drone_ip> \\
  --port ${28002 + activeFleet.length + 1} \\
  --gcs-ip ${typeof window !== "undefined" ? window.location.hostname : "127.0.0.1"} \\
  --gcs-port 28001 \\
  --ca-ip ${typeof window !== "undefined" ? window.location.hostname : "127.0.0.1"} \\
  --ca-port 28000`}
                </pre>
              </div>

              <div className="rounded bg-primary/10 border border-primary/20 p-2.5 text-[11px] text-primary flex items-start gap-2">
                <span>Once launched, the board automatically registers its PQ cert with the CA, runs handshakes, and joins the active TreeKEM swarm roster dynamically.</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </AppShell>
  );
}

function Th({ children, onClick, active, dir, align = "left" }: { children: React.ReactNode; onClick?: () => void; active?: boolean; dir?: "asc" | "desc"; align?: "left" | "right" }) {
  return (
    <th className={`px-3 py-2.5 font-medium ${align === "right" ? "text-right" : ""}`}>
      <button onClick={onClick} className={`inline-flex items-center gap-1 hover:text-foreground ${active ? "text-foreground" : ""}`}>
        <span>{children}</span>
        <ArrowUpDown className={`h-3 w-3 ${active ? "opacity-100" : "opacity-40"}`} />
        {active && <span className="text-tabular text-[9px]">{dir === "asc" ? "↑" : "↓"}</span>}
      </button>
    </th>
  );
}
