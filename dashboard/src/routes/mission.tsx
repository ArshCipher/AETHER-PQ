import { createFileRoute, Link } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import {
  Battery, Cpu, Gauge, Signal, Radio, ChevronDown, ChevronRight,
  ShieldCheck, Wifi, MemoryStick, Route as RouteIcon, MapPin, Clock, Filter, Video,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { Sparkline } from "@/components/mini-chart";
import { LiveClock } from "@/components/live";
import { type UAV } from "@/lib/types";
import { useWebSocketContext } from "@/components/websocket-provider";

export const Route = createFileRoute("/mission")({
  head: () => ({
    meta: [
      { title: "Mission Control — AETHER-PQ" },
      { name: "description", content: "Flagship operational view of the entire UAV fleet with live telemetry, cryptographic posture, and policy state." },
    ],
  }),
  component: MissionControl,
});

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

function MeterBar({ value, tone = "primary" }: { value: number; tone?: "primary" | "success" | "warning" | "critical" }) {
  const c =
    tone === "success" ? "var(--color-success)" :
    tone === "warning" ? "var(--color-warning)" :
    tone === "critical" ? "var(--color-critical)" :
    "var(--color-primary)";
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-2">
      <div className="h-full rounded-full transition-all" style={{ width: `${Math.max(0, Math.min(100, value))}%`, background: c }} />
    </div>
  );
}

function batteryTone(v: number) {
  return v < 20 ? "critical" : v < 40 ? "warning" : "success";
}

function Metric({ icon: Icon, label, value, unit, tone }: { icon: any; label: string; value: string | number; unit?: string; tone?: "success" | "warning" | "critical" | "neutral" }) {
  const c =
    tone === "success" ? "text-success" :
    tone === "warning" ? "text-warning" :
    tone === "critical" ? "text-critical" :
    "text-foreground";
  return (
    <div>
      <div className="flex items-center gap-1.5 text-[10.5px] uppercase tracking-wider text-muted-foreground">
        <Icon className="h-3 w-3" strokeWidth={2} />
        <span>{label}</span>
      </div>
      <div className={`mt-0.5 text-tabular text-[14px] font-semibold leading-tight ${c}`}>
        {value}{unit && <span className="ml-0.5 text-[11px] font-normal text-muted-foreground">{unit}</span>}
      </div>
    </div>
  );
}

function UavCard({ u }: { u: UAV }) {
  const [open, setOpen] = useState(false);
  const bat = batteryTone(u.battery);
  const cpuTone = u.cpu > 80 ? "critical" : u.cpu > 60 ? "warning" : "success";
  const latTone = u.latency > 200 ? "critical" : u.latency > 150 ? "warning" : "success";

  return (
    <article className="overflow-hidden rounded-lg border border-border bg-card shadow-xs transition-shadow hover:shadow-sm">
      {/* Header */}
      <header className="flex items-start justify-between gap-4 border-b border-border px-4 py-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-tabular text-[13px] font-semibold text-foreground">{u.id}</span>
            <span className="text-[12px] text-muted-foreground">·</span>
            <span className="text-[12.5px] font-medium text-foreground">{u.callsign}</span>
            <StatusPill tone={statusTone[u.status]}>{u.status.toUpperCase()}</StatusPill>
          </div>
          <div className="mt-0.5 flex items-center gap-1.5 text-[11.5px] text-muted-foreground">
            <RouteIcon className="h-3 w-3" />
            <span className="truncate">{u.mission}</span>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <span className="rounded-md border border-border bg-surface px-1.5 py-0.5 text-tabular text-[10px] text-muted-foreground">
            GRP · {u.fleetGroup}
          </span>
          <span className="rounded-md border border-border bg-surface px-1.5 py-0.5 text-tabular text-[10px] text-muted-foreground">
            {u.link}
          </span>
        </div>
      </header>

      {/* Primary metrics */}
      <div className="grid grid-cols-4 gap-4 px-4 py-3">
        <div className="col-span-4 sm:col-span-2 lg:col-span-1">
          <div className="flex items-center gap-1.5 text-[10.5px] uppercase tracking-wider text-muted-foreground">
            <Battery className="h-3 w-3" /> Battery
          </div>
          <div className={`mt-0.5 flex items-baseline gap-1 text-tabular text-[16px] font-semibold text-${bat === "critical" ? "critical" : bat === "warning" ? "warning" : "success"}`}
               style={{ color: `var(--color-${bat === "critical" ? "critical" : bat === "warning" ? "warning" : "success"})` }}>
            {u.battery}<span className="text-[11px] font-normal text-muted-foreground">%</span>
          </div>
          <div className="mt-1.5"><MeterBar value={u.battery} tone={bat} /></div>
          <div className="mt-1 text-tabular text-[10.5px] text-muted-foreground">{u.energy} Wh remaining</div>
        </div>
        <Metric icon={Gauge} label="Speed" value={u.speed.toFixed(1)} unit="m/s" />
        <Metric icon={Signal} label="RSSI" value={u.rssi} unit="dBm" tone={u.rssi < -85 ? "warning" : undefined} />
        <Metric icon={Radio} label="SINR" value={u.sinr.toFixed(1)} unit="dB" tone={u.sinr < 8 ? "warning" : undefined} />
        <Metric icon={Wifi} label="Latency" value={u.latency} unit="ms" tone={latTone} />
        <Metric icon={Signal} label="Packet Loss" value={u.packetLoss.toFixed(1)} unit="%" tone={u.packetLoss > 2 ? "warning" : undefined} />
        <Metric icon={Cpu} label="CPU" value={u.cpu} unit="%" tone={cpuTone} />
        <Metric icon={MemoryStick} label="Memory" value={u.memory} unit="%" />
      </div>

      {/* Sparkline row */}
      <div className="grid grid-cols-3 gap-4 border-t border-border px-4 py-3">
        <div>
          <div className="mb-1 flex items-center justify-between text-[10.5px] uppercase tracking-wider text-muted-foreground">
            <span>Link Latency</span><span className="text-tabular">{u.latency} ms</span>
          </div>
          <Sparkline data={[{ t: 0, v: u.latency }]} tone={latTone === "critical" ? "critical" : latTone === "warning" ? "warning" : "primary"} height={36} />
        </div>
        <div>
          <div className="mb-1 flex items-center justify-between text-[10.5px] uppercase tracking-wider text-muted-foreground">
            <span>Battery</span><span className="text-tabular">{u.battery}%</span>
          </div>
          <Sparkline data={[{ t: 0, v: u.battery }]} tone={bat} height={36} />
        </div>
        <div>
          <div className="mb-1 flex items-center justify-between text-[10.5px] uppercase tracking-wider text-muted-foreground">
            <span>CPU</span><span className="text-tabular">{u.cpu}%</span>
          </div>
          <Sparkline data={[{ t: 0, v: u.cpu }]} tone={cpuTone === "critical" ? "critical" : cpuTone === "warning" ? "warning" : "primary"} height={36} />
        </div>
      </div>

      {/* Crypto / mode strip */}
      <div className="grid grid-cols-3 gap-0 border-t border-border bg-surface text-[11.5px]">
        <div className="border-r border-border px-4 py-2.5">
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Operating Mode</div>
          <div className="mt-0.5 text-tabular font-medium text-foreground">{u.operatingMode}</div>
        </div>
        <div className="border-r border-border px-4 py-2.5">
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Crypto Profile</div>
          <div className="mt-0.5 flex items-center gap-1.5">
            <ShieldCheck className="h-3 w-3 text-primary" />
            <span className="text-tabular font-medium text-foreground">{u.cryptoProfile}</span>
          </div>
        </div>
        <div className="px-4 py-2.5">
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Policy Mode</div>
          <div className="mt-0.5 text-tabular font-medium text-foreground">{u.policyMode}</div>
        </div>
      </div>

      {/* Expander */}
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between border-t border-border bg-surface-2 px-4 py-2 text-[12px] text-muted-foreground hover:bg-surface-3"
      >
        <span className="flex items-center gap-1.5">
          {open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
          {open ? "Hide details" : "Show details"}
        </span>
        <span className="text-tabular text-[10.5px]">last frame · {u.lastFrameMs} ms ago</span>
      </button>

      {open && (
        <div className="grid grid-cols-2 gap-x-6 gap-y-2 border-t border-border bg-background px-4 py-3 text-[12px] md:grid-cols-4">
          <Detail label="Altitude" value={`${u.altitude} m`} />
          <Detail label="Heading" value={`${u.heading}°`} />
          <Detail label="Bandwidth" value={`${u.bandwidth} Mbps`} />
          <Detail label="Temperature" value={`${u.temperature} °C`} />
          <Detail label="TreeKEM Epoch" value={`e-${u.epoch}`} />
          <Detail label="Coordinates" value={`${u.coord.lat}, ${u.coord.lon}`} icon={MapPin} />
          <Detail label="Fleet Group" value={u.fleetGroup} />
          <Detail label="Link" value={u.link} />
        </div>
      )}
    </article>
  );
}

function Detail({ label, value, icon: Icon }: { label: string; value: string; icon?: any }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className="mt-0.5 flex items-center gap-1 text-tabular font-medium text-foreground">
        {Icon && <Icon className="h-3 w-3 text-muted-foreground" />}
        {value}
      </div>
    </div>
  );
}

function MissionControl() {
  const { data, status, sendCommand } = useWebSocketContext();

  if (status !== "open" || !data) {
    return (
      <AppShell
        eyebrow="Mission Control · Live"
        title="Mission Swarm Control"
        breadcrumbs={[{ label: "Command", to: "/" }, { label: "Mission Control" }]}
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

  const [filter, setFilter] = useState<"all" | UAV["status"]>("all");
  const [group, setGroup] = useState<"ALL" | UAV["fleetGroup"]>("ALL");

  const filtered = useMemo(() => {
    return activeFleet.filter((u: any) => (filter === "all" || u.status === filter) && (group === "ALL" || u.fleetGroup === group));
  }, [filter, group, activeFleet]);

  const counts = {
    all: activeFleet.length,
    nominal: activeFleet.filter((u: any) => u.status === "nominal").length,
    degraded: activeFleet.filter((u: any) => u.status === "degraded").length,
    critical: activeFleet.filter((u: any) => u.status === "critical").length,
    offline: activeFleet.filter((u: any) => u.status === "offline").length,
    maintenance: activeFleet.filter((u: any) => u.status === "maintenance").length,
  };

  return (
    <AppShell
      eyebrow="Command · Operations"
      title="Mission Control"
      breadcrumbs={[{ label: "Command", to: "/" }, { label: "Mission Control" }]}
      actions={
        <>
          <div className="flex items-center gap-1.5 rounded-md border border-border bg-background px-2.5 py-1.5 text-[12px]">
            <Clock className="h-3.5 w-3.5 text-muted-foreground" />
            <span className="text-tabular text-muted-foreground">Live · <LiveClock /></span>
          </div>
          <Link
            to="/recordings"
            className="rounded-md border border-border bg-background px-3 py-1.5 text-[12.5px] font-medium text-foreground hover:bg-surface-2 transition-colors inline-flex items-center gap-1.5"
          >
            <Video className="h-3.5 w-3.5 text-primary" />
            Mission Recordings
          </Link>
          <button 
            onClick={() => sendCommand("rekey")}
            className="rounded-md bg-primary px-3 py-1.5 text-[12.5px] font-medium text-primary-foreground hover:opacity-90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring cursor-pointer"
          >
            Broadcast Rekey
          </button>
        </>
      }
    >
      {/* Filter bar */}
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-card px-4 py-3 shadow-xs">
        <div className="flex flex-wrap items-center gap-1">
          {[
            { key: "all" as const, label: "All", count: counts.all, tone: "neutral" as const },
            { key: "nominal" as const, label: "Nominal", count: counts.nominal, tone: "success" as const },
            { key: "degraded" as const, label: "Degraded", count: counts.degraded, tone: "warning" as const },
            { key: "critical" as const, label: "Critical", count: counts.critical, tone: "critical" as const },
            { key: "offline" as const, label: "Offline", count: counts.offline, tone: "neutral" as const },
            { key: "maintenance" as const, label: "Maintenance", count: counts.maintenance, tone: "neutral" as const },
          ].map((t) => (
            <button
              key={t.key}
              onClick={() => setFilter(t.key)}
              className={`inline-flex items-center gap-2 rounded-md border px-2.5 py-1 text-[12px] transition-colors ${
                filter === t.key
                  ? "border-primary bg-primary/5 text-primary"
                  : "border-border bg-background text-foreground/80 hover:bg-surface-2"
              }`}
            >
              <span>{t.label}</span>
              <span className="text-tabular text-[10.5px] text-muted-foreground">{t.count}</span>
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 text-[11.5px] text-muted-foreground">
            <Filter className="h-3.5 w-3.5" /> Group
          </div>
          <select
            value={group}
            onChange={(e) => setGroup(e.target.value as any)}
            className="h-8 rounded-md border border-border bg-background px-2 text-[12.5px] outline-none focus:border-primary"
          >
            <option value="ALL">All groups</option>
            <option value="ALPHA">ALPHA</option>
            <option value="BRAVO">BRAVO</option>
            <option value="CHARLIE">CHARLIE</option>
          </select>
          <div className="text-tabular text-[11.5px] text-muted-foreground">
            Showing <span className="font-semibold text-foreground">{filtered.length}</span> of {activeFleet.length}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 2xl:grid-cols-3">
        {filtered.map((u) => (
          <UavCard key={u.id} u={u} />
        ))}
      </div>
    </AppShell>
  );
}
