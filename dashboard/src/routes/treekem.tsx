import { createFileRoute, Link } from "@tanstack/react-router";
import { useState, useMemo } from "react";
import {
  Network, UserPlus, UserMinus, KeyRound, Users, Layers,
  Clock, RefreshCw, ArrowUpRight, CheckCircle2, Loader2,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { Sparkline } from "@/components/mini-chart";
import { type UAV } from "@/lib/types";
import { useWebSocketContext } from "@/components/websocket-provider";

export const Route = createFileRoute("/treekem")({
  head: () => ({
    meta: [
      { title: "TreeKEM Management — AETHER-PQ" },
      { name: "description", content: "Continuous group key agreement — tree topology, member roster, epoch history, and pending join/leave operations. Metadata only." },
    ],
  }),
  component: TreeKEM,
});

function Pill({ tone, children }: { tone: "success" | "warning" | "critical" | "neutral" | "info"; children: React.ReactNode }) {
  const cls = {
    success: "bg-success-muted text-success",
    warning: "bg-warning-muted text-warning",
    critical: "bg-critical-muted text-critical",
    neutral: "bg-surface-2 text-muted-foreground",
    info: "bg-primary-muted text-primary",
  }[tone];
  return <span className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-[11px] font-medium ${cls}`}>{children}</span>;
}

// ---- Tree model (metadata only) ----------------------------------------
type LeafState = "member" | "pending-join" | "pending-leave" | "blank";
type Leaf = { id: string; label: string; role: string; state: LeafState };



// Build parent nodes bottom-up
type TreeNode = {
  depth: number;
  leaves: Leaf[];
  status: "populated" | "partial" | "blanked" | "pending";
  path: string;
};

function buildTree(leaves: Leaf[]): TreeNode[][] {
  const levels: TreeNode[][] = [];
  // level 0 = leaves
  levels.push(
    leaves.map((l, i) => ({
      depth: 0,
      leaves: [l],
      status:
        l.state === "blank" ? "blanked" :
        l.state === "pending-join" ? "pending" :
        l.state === "pending-leave" ? "pending" :
        "populated",
      path: `L0-${i}`,
    })),
  );
  for (let d = 1; d <= 4; d++) {
    const prev = levels[d - 1];
    const cur: TreeNode[] = [];
    for (let i = 0; i < prev.length; i += 2) {
      const a = prev[i], b = prev[i + 1];
      const kids = [a, b].filter(Boolean);
      const all = kids.flatMap((k) => k.leaves);
      const anyPending = kids.some((k) => k.status === "pending");
      const anyMember = all.some((l) => l.state === "member");
      const anyBlank = all.some((l) => l.state === "blank");
      const status: TreeNode["status"] =
        anyPending ? "pending" :
        !anyMember ? "blanked" :
        anyBlank ? "partial" : "populated";
      cur.push({ depth: d, leaves: all, status, path: `L${d}-${i / 2}` });
    }
    levels.push(cur);
  }
  return levels;
}

function TreeKEM() {
  const { data, status, sendCommand } = useWebSocketContext();

  if (status !== "open" || !data) {
    return (
      <AppShell
        eyebrow="Security · Swarm"
        title="TreeKEM Management"
        breadcrumbs={[{ label: "Security", to: "/" }, { label: "TreeKEM" }]}
      >
        <div className="flex h-[400px] flex-col items-center justify-center rounded-lg border border-border bg-card p-8 text-center shadow-xs">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
          <h2 className="mt-4 text-[16px] font-semibold text-foreground">Waiting for backend connection...</h2>
          <p className="mt-2 text-[13px] text-muted-foreground">The Swarmlink control server is offline or disconnected.</p>
        </div>
      </AppShell>
    );
  }

  const activeFleet = data.fleet || [];
  const activeActivity = data.recentActivity || [];
  const [selectedMember, setSelectedMember] = useState<string | null>(null);

  const pending: any[] = [];
  const kemLatency = [data.treekem?.rekeyDurationMs || 0];
  const memberSpark = [activeFleet.length];

  const epochHistory = activeActivity
    .filter((a: any) => a.kind === "rotation")
    .map((a: any, i: number) => ({
      epoch: data.treekem?.epoch - i,
      ts: a.ts,
      event: a.message,
      size: activeFleet.length,
      driver: a.actor
    }));

  const activeLeaves = useMemo(() => {
    const list: Leaf[] = [
      { id: "GCS-01", label: "GCS-01", role: "Ground Control · Primary", state: "member" },
      { id: "GCS-02", label: "GCS-02", role: "Ground Control · Standby", state: "member" },
      { id: "ACPE", label: "ACPE", role: "Policy Engine", state: "member" },
      { id: "CA", label: "CA-INT", role: "Cert Authority", state: "member" },
    ];
    for (const u of activeFleet) {
      list.push({
        id: u.id,
        label: u.id,
        role: u.callsign,
        state: u.status === "nominal" ? "member" : u.status === "offline" ? "blank" : "pending-join"
      });
    }
    // Pad to 8 or 16 elements
    while (list.length < 8) {
      list.push({ id: `BLANK-${list.length}`, label: "—", role: "Blanked slot", state: "blank" });
    }
    return list;
  }, [activeFleet]);

  const tree = buildTree(activeLeaves);
  const totalLeaves = activeLeaves.length;
  const members = activeLeaves.filter((l) => l.state === "member").length;
  const pendingCount = activeLeaves.filter((l) => l.state === "pending-join" || l.state === "pending-leave").length;

  const isUavSelected = selectedMember?.startsWith("UAV-");

  return (
    <AppShell
      eyebrow="Security · Group Key Agreement"
      title="TreeKEM Management"
      breadcrumbs={[{ label: "Security", to: "/security" }, { label: "TreeKEM Management" }]}
      actions={
        <>
          <button disabled className="inline-flex items-center gap-1.5 rounded-md border border-border bg-background px-3 py-1.5 text-[12.5px] font-medium opacity-50 cursor-not-allowed" title="Feature not implemented by backend.">
            <UserPlus className="h-3.5 w-3.5" /> Add Member
          </button>
          <button 
            disabled={!isUavSelected}
            onClick={() => {
              if (selectedMember) {
                sendCommand("revoke", { id: selectedMember });
                setSelectedMember(null);
              }
            }}
            className={`inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-[12.5px] font-medium transition-colors ${
              isUavSelected 
                ? "border-destructive bg-destructive/10 text-destructive hover:bg-destructive/20 cursor-pointer" 
                : "border-border bg-background opacity-50 cursor-not-allowed"
            }`}
            title={isUavSelected ? "Revoke selected member from group" : "Select a UAV member below to remove"}
          >
            <UserMinus className="h-3.5 w-3.5" /> Remove
          </button>
          <button 
            onClick={() => sendCommand("rekey")}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-[12.5px] font-medium text-primary-foreground hover:opacity-90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring cursor-pointer"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Rotate Epoch
          </button>
        </>
      }
    >
      {/* Statistics strip */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
        <Stat label="Current Epoch" value="e-1442" sub="4m 12s ago" />
        <Stat label="Members" value={`${members}`} sub={`${totalLeaves} slots`} tone="primary" spark={memberSpark} />
        <Stat label="Pending Ops" value={`${pendingCount + 1}`} sub="join / leave / rekey" tone="warning" />
        <Stat label="Rekeys · 24h" value="18" sub="12 auto · 6 policy" />
        <Stat label="KEM Latency" value="42 ms" sub="ML-KEM-768 encaps" spark={kemLatency} />
      </div>

      {/* Tree Structure */}
      <section className="mt-6 rounded-lg border border-border bg-card shadow-xs">
        <header className="flex items-center justify-between border-b border-border px-5 py-3.5">
          <div>
            <div className="text-overline">Topology</div>
            <div className="mt-0.5 flex items-center gap-2 text-[15px] font-semibold text-foreground">
              <Network className="h-4 w-4 text-primary" />
              Tree Structure · balanced binary · depth 4
            </div>
          </div>
          <div className="flex items-center gap-3 text-[11.5px] text-muted-foreground">
            <LegendDot tone="success" label="Populated" />
            <LegendDot tone="warning" label="Pending" />
            <LegendDot tone="neutral" label="Partial" />
            <LegendDot tone="critical" label="Blanked" />
          </div>
        </header>

        <div className="overflow-x-auto p-6">
          <div className="min-w-[840px]">
            {/* Render levels top-down (root first) */}
            <div className="space-y-3">
              {[...tree].reverse().map((level, ri) => {
                const isLeafLevel = ri === tree.length - 1;
                return (
                  <div key={ri} className="relative">
                    <div className="grid gap-2" style={{ gridTemplateColumns: `repeat(${level.length}, minmax(0, 1fr))` }}>
                      {level.map((n) => {
                        const tone =
                          n.status === "pending"  ? "warning" :
                          n.status === "blanked"  ? "critical" :
                          n.status === "partial"  ? "neutral" :
                          "success";
                        const bg =
                          tone === "success"  ? "border-success/40 bg-success-muted/50" :
                          tone === "warning"  ? "border-warning/40 bg-warning-muted/60" :
                          tone === "critical" ? "border-critical/40 bg-critical-muted/50" :
                          "border-border bg-surface";
                        return (
                          <div key={n.path} className="flex justify-center">
                            <div className={`w-full max-w-[110px] rounded-md border px-2 py-1.5 text-center ${bg}`}>
                              {isLeafLevel ? (
                                <>
                                  <div className="text-tabular text-[10.5px] font-semibold text-foreground truncate">{n.leaves[0].label}</div>
                                  <div className="text-[9.5px] text-muted-foreground truncate">{n.leaves[0].role}</div>
                                </>
                              ) : (
                                <>
                                  <div className="text-tabular text-[10px] uppercase tracking-wider text-muted-foreground">{n.path}</div>
                                  <div className="text-tabular text-[11.5px] font-semibold text-foreground">
                                    {n.leaves.filter((l) => l.state === "member").length}/{n.leaves.length}
                                  </div>
                                </>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                    {ri < tree.length - 1 && (
                      <div className="pointer-events-none mt-1 grid" style={{ gridTemplateColumns: `repeat(${level.length}, minmax(0, 1fr))` }}>
                        {level.map((_, i) => (
                          <svg key={i} viewBox="0 0 100 16" className="h-3 w-full" preserveAspectRatio="none">
                            <path d="M 50 0 L 50 8 L 25 8 L 25 16 M 50 8 L 75 8 L 75 16" stroke="var(--color-border)" strokeWidth="1" fill="none" />
                          </svg>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        <div className="border-t border-border bg-surface px-5 py-2.5 text-[11px] text-muted-foreground">
          <Layers className="mr-1.5 inline h-3 w-3" />
          Metadata view · displays roles and slot occupancy only. Public keys, secrets, and path secrets are never rendered.
        </div>
      </section>

      {/* Members + Pending */}
      <section className="mt-6 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="rounded-lg border border-border bg-card shadow-xs xl:col-span-2">
          <header className="flex items-center justify-between border-b border-border px-5 py-3.5">
            <div>
              <div className="text-overline">Roster</div>
              <div className="mt-0.5 flex items-center gap-2 text-[15px] font-semibold text-foreground">
                <Users className="h-4 w-4 text-muted-foreground" />
                Group Members · e-{data?.treekem?.epoch || 1442}
              </div>
            </div>
            <div className="text-tabular text-[11.5px] text-muted-foreground">
              {members} member{members !== 1 ? "s" : ""} · {pendingCount} pending
            </div>
          </header>
          <div className="overflow-x-auto">
            <table className="w-full text-[13px]">
              <thead className="border-b border-border bg-surface">
                <tr className="text-left text-[11px] uppercase tracking-wider text-muted-foreground">
                  <th className="px-4 py-2.5 font-medium">Member</th>
                  <th className="px-4 py-2.5 font-medium">Role</th>
                  <th className="px-4 py-2.5 font-medium">Leaf Path</th>
                  <th className="px-4 py-2.5 font-medium">Key ID (hash)</th>
                  <th className="px-4 py-2.5 font-medium">State</th>
                </tr>
              </thead>
              <tbody>
                {activeLeaves.filter((l) => l.state !== "blank").map((l, i) => {
                  const isSelected = selectedMember === l.id;
                  const isUav = l.id.startsWith("UAV-");
                  return (
                    <tr 
                      key={l.id} 
                      onClick={() => {
                        if (isUav) {
                          setSelectedMember(isSelected ? null : l.id);
                        }
                      }}
                      className={`border-b border-border last:border-b-0 hover:bg-surface cursor-pointer select-none transition-colors ${
                        isSelected 
                          ? "bg-primary/10 text-primary hover:bg-primary/15" 
                          : i % 2 
                            ? "bg-surface/40" 
                            : ""
                      }`}
                    >
                      <td className="px-4 py-2.5 text-tabular font-medium text-foreground">{l.label}</td>
                      <td className="px-4 py-2.5 text-muted-foreground">{l.role}</td>
                      <td className="px-4 py-2.5 text-tabular text-[11.5px] text-muted-foreground">L0-{i}</td>
                      <td className="px-4 py-2.5 text-tabular text-[11.5px] text-muted-foreground">
                        sha256:{(i * 37 + 128).toString(16).padStart(2, "0")}·{(i * 91).toString(16).padStart(2, "0")}·••·••
                      </td>
                      <td className="px-4 py-2.5">
                        <Pill tone={l.state === "member" ? "success" : "warning"}>
                          {l.state === "pending-join" ? "PENDING JOIN" : l.state === "pending-leave" ? "PENDING LEAVE" : "MEMBER"}
                        </Pill>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        <div className="rounded-lg border border-border bg-card shadow-xs">
          <header className="flex items-center justify-between border-b border-border px-5 py-3.5">
            <div>
              <div className="text-overline">Queue</div>
              <div className="mt-0.5 text-[15px] font-semibold text-foreground">Pending Operations</div>
            </div>
            <Pill tone="warning">{pending.length}</Pill>
          </header>
          <ul>
            {pending.map((p) => {
              const Icon = p.kind === "join" ? UserPlus : p.kind === "leave" ? UserMinus : RefreshCw;
              const tone = p.kind === "leave" ? "critical" : p.kind === "rekey" ? "info" : "success";
              return (
                <li key={p.id} className="border-b border-border px-5 py-3 last:border-b-0 hover:bg-surface">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className={`flex h-6 w-6 items-center justify-center rounded-md ${
                        tone === "critical" ? "bg-critical-muted text-critical" :
                        tone === "info" ? "bg-primary-muted text-primary" :
                        "bg-success-muted text-success"
                      }`}>
                        <Icon className="h-3 w-3" />
                      </div>
                      <span className="text-tabular text-[12px] font-medium text-foreground">{p.id}</span>
                    </div>
                    <Pill tone={tone}>{p.kind.toUpperCase()}</Pill>
                  </div>
                  <div className="mt-1.5 text-[12.5px] font-medium text-foreground">{p.member}</div>
                  <div className="mt-0.5 flex items-center justify-between text-[11px] text-muted-foreground">
                    <span className="text-tabular">path · {p.path}</span>
                    <span className="inline-flex items-center gap-1"><Clock className="h-3 w-3" /> {p.eta}</span>
                  </div>
                  <div className="mt-1 text-[11px] text-muted-foreground">by {p.by}</div>
                </li>
              );
            })}
          </ul>
        </div>
      </section>

      {/* Epoch history */}
      <section className="mt-6 rounded-lg border border-border bg-card shadow-xs">
        <header className="flex items-center justify-between border-b border-border px-5 py-3.5">
          <div>
            <div className="text-overline">History</div>
            <div className="mt-0.5 flex items-center gap-2 text-[15px] font-semibold text-foreground">
              <KeyRound className="h-4 w-4 text-muted-foreground" />
              Epoch History
            </div>
          </div>
          <Link to="/logs" className="text-[12px] text-primary hover:underline flex items-center gap-0.5">Full audit trail <ArrowUpRight className="h-3 w-3" /></Link>
        </header>
        <div className="overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead className="border-b border-border bg-surface">
              <tr className="text-left text-[11px] uppercase tracking-wider text-muted-foreground">
                <th className="px-4 py-2.5 font-medium">Epoch</th>
                <th className="px-4 py-2.5 font-medium">Timestamp</th>
                <th className="px-4 py-2.5 font-medium">Event</th>
                <th className="px-4 py-2.5 font-medium">Group Size</th>
                <th className="px-4 py-2.5 font-medium">Driver</th>
                <th className="px-4 py-2.5 font-medium">Confirmation</th>
              </tr>
            </thead>
            <tbody>
              {epochHistory.map((e, i) => (
                <tr key={e.epoch} className={`border-b border-border last:border-b-0 hover:bg-surface ${i % 2 ? "bg-surface/40" : ""}`}>
                  <td className="px-4 py-2.5 text-tabular font-medium text-foreground">e-{e.epoch}</td>
                  <td className="px-4 py-2.5 text-tabular text-[11.5px] text-muted-foreground">{e.ts}</td>
                  <td className="px-4 py-2.5 text-[12.5px]">{e.event}</td>
                  <td className="px-4 py-2.5 text-tabular text-[12px]">{e.size}</td>
                  <td className="px-4 py-2.5 text-[12px] text-muted-foreground">{e.driver}</td>
                  <td className="px-4 py-2.5">
                    <span className="inline-flex items-center gap-1.5 text-tabular text-[11px] text-success">
                      <CheckCircle2 className="h-3 w-3" /> confirmed · {e.size}/{e.size}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </AppShell>
  );
}

function Stat({ label, value, sub, tone, spark }: {
  label: string; value: string; sub?: string;
  tone?: "primary" | "success" | "warning" | "critical" | "neutral";
  spark?: number[];
}) {
  return (
    <div className="rounded-lg border border-border bg-card p-4 shadow-xs">
      <div className="text-overline">{label}</div>
      <div className="mt-2 flex items-baseline gap-2">
        <div className="text-tabular text-[22px] font-semibold leading-none tracking-tight text-foreground">{value}</div>
        {sub && <div className="text-[11.5px] text-muted-foreground">{sub}</div>}
      </div>
      {spark && <div className="mt-2 -mx-1"><Sparkline data={spark.map((v, i) => ({ t: i, v }))} tone={tone ?? "primary"} /></div>}
    </div>
  );
}

function LegendDot({ tone, label }: { tone: "success" | "warning" | "critical" | "neutral"; label: string }) {
  const c =
    tone === "success" ? "var(--color-success)" :
    tone === "warning" ? "var(--color-warning)" :
    tone === "critical" ? "var(--color-critical)" :
    "var(--color-muted-foreground)";
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="h-2 w-2 rounded-sm" style={{ background: c }} />
      <span>{label}</span>
    </span>
  );
}
