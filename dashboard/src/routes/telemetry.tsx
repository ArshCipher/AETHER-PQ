import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Clock, Download } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { ProChart, ProBars } from "@/components/mini-chart";
import { type UAV } from "@/lib/types";
import { useWebSocketContext } from "@/components/websocket-provider";
import { LiveClock } from "@/components/live";

export const Route = createFileRoute("/telemetry")({
  head: () => ({
    meta: [
      { title: "Telemetry — AETHER-PQ" },
      { name: "description", content: "Time-series telemetry across the UAV fleet: battery, energy, speed, altitude, RSSI, SINR, latency, bandwidth, CPU, memory." },
    ],
  }),
  component: TelemetryPage,
});

type Range = "5m" | "15m" | "1h" | "6h" | "24h";

const CHANNELS = [
  { key: "battery",   label: "Battery",    unit: "%",    base: 62,  jitter: 1.2, tone: "success" as const, seed: 501, domain: [0, 100] as [number, number] },
  { key: "energy",    label: "Energy",     unit: " Wh",  base: 284, jitter: 4,   tone: "success" as const, seed: 502 },
  { key: "speed",     label: "Speed",      unit: " m/s", base: 18.4,jitter: 1.4, tone: "primary" as const, seed: 503 },
  { key: "altitude",  label: "Altitude",   unit: " m",   base: 240, jitter: 10,  tone: "primary" as const, seed: 504 },
  { key: "rssi",      label: "RSSI",       unit: " dBm", base: -74, jitter: 3,   tone: "primary" as const, seed: 505 },
  { key: "sinr",      label: "SINR",       unit: " dB",  base: 16.2,jitter: 1.6, tone: "primary" as const, seed: 506 },
  { key: "latency",   label: "Latency",    unit: " ms",  base: 128, jitter: 12,  tone: "warning" as const, seed: 507 },
  { key: "bandwidth", label: "Bandwidth",  unit: " Mbps",base: 62.4,jitter: 5,   tone: "primary" as const, seed: 508, bars: true },
  { key: "cpu",       label: "CPU",        unit: "%",    base: 46,  jitter: 5,   tone: "primary" as const, seed: 509, domain: [0, 100] as [number, number] },
  { key: "memory",    label: "Memory",     unit: "%",    base: 58,  jitter: 3,   tone: "primary" as const, seed: 510, domain: [0, 100] as [number, number] },
];import { useMemo, useEffect } from "react";

function TelemetryPage() {
  const { data, status } = useWebSocketContext();

  if (status !== "open" || !data) {
    return (
      <AppShell
        eyebrow="Research · Telemetry"
        title="Telemetry"
        breadcrumbs={[{ label: "Research", to: "/" }, { label: "Telemetry" }]}
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
  const [range, setRange] = useState<Range>("5m");
  const [target, setTarget] = useState<string>("FLEET");

  const currentValues = useMemo(() => {
    const vals: Record<string, number> = {};
    const uavs = target === "FLEET" ? activeFleet : activeFleet.filter((u: any) => u.id === target);
    const count = uavs.length;
    for (const c of CHANNELS) {
      if (count === 0) {
        vals[c.key] = 0;
      } else {
        const sum = uavs.reduce((acc: number, u: any) => acc + (u[c.key as keyof UAV] as number || 0), 0);
        vals[c.key] = c.key === "bandwidth" || c.key === "speed" || c.key === "latency" || c.key === "sinr"
          ? Math.round((sum / count) * 10) / 10
          : Math.round(sum / count);
      }
    }
    return vals;
  }, [activeFleet, target]);

  const [history, setHistory] = useState<Record<string, { t: string; v: number }[]>>({});

  useEffect(() => {
    const timeStr = new Date().toLocaleTimeString();
    setHistory((prev) => {
      const next = { ...prev };
      for (const c of CHANNELS) {
        const val = currentValues[c.key] || 0;
        const channelHistory = prev[c.key] || [];
        next[c.key] = [...channelHistory.slice(-59), { t: timeStr, v: val }];
      }
      return next;
    });
  }, [currentValues]);

  const exportSeriesJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify({ target, range, timestamp: new Date().toISOString(), series: history }, null, 2));
    const link = document.createElement("a");
    link.setAttribute("href", dataStr);
    link.setAttribute("download", `aether_pq_telemetry_${target.toLowerCase()}_${new Date().toISOString().slice(0,10)}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <AppShell
      eyebrow="Research · Telemetry"
      title="Telemetry"
      breadcrumbs={[{ label: "Research", to: "/" }, { label: "Telemetry" }]}
      actions={
        <>
          <div className="flex items-center gap-1.5 rounded-md border border-border bg-background px-2.5 py-1.5 text-[12px]">
            <Clock className="h-3.5 w-3.5 text-muted-foreground" />
            <span className="text-tabular text-muted-foreground">Live · <LiveClock /></span>
          </div>
          <button 
            onClick={exportSeriesJson}
            className="inline-flex items-center gap-1.5 rounded-md border border-border bg-background px-3 py-1.5 text-[12.5px] font-medium hover:bg-surface-2 cursor-pointer focus:outline-none"
          >
            <Download className="h-3.5 w-3.5" /> Export Series
          </button>
        </>
      }
    >
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-card px-4 py-3 shadow-xs">
        <div className="flex items-center gap-3">
          <span className="text-[11.5px] text-muted-foreground">Target</span>
          <select value={target} onChange={(e) => setTarget(e.target.value)} className="h-8 rounded-md border border-border bg-background px-2 text-[12.5px] outline-none focus:border-primary">
            <option value="FLEET">Fleet aggregate</option>
            {activeFleet.map((u: any) => (
              <option key={u.id} value={u.id}>{u.id} · {u.callsign}</option>
            ))}
          </select>
        </div>
        <div className="flex items-center gap-1 rounded-md border border-border bg-background p-0.5">
          {(["5m", "15m", "1h", "6h", "24h"] as Range[]).map((r) => {
            const is5m = r === "5m";
            return (
              <button
                key={r}
                disabled={!is5m}
                onClick={() => setRange(r)}
                className={`rounded px-2.5 py-1 text-[11.5px] font-medium transition-colors ${
                  range === r 
                    ? "bg-primary text-primary-foreground" 
                    : is5m 
                      ? "text-muted-foreground hover:bg-surface-2 cursor-pointer" 
                      : "text-muted-foreground opacity-50 cursor-not-allowed"
                }`}
                title={is5m ? "Show 5m telemetry" : "Only 5m real-time history is stored in memory."}
              >
                {r}
              </button>
            );
          })}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {CHANNELS.map((c) => {
          const pts = history[c.key] || [];
          const cur = pts[pts.length - 1]?.v ?? 0;
          const first = pts[0]?.v ?? 0;
          const delta = cur - first;
          return (
            <section key={c.key} className="rounded-lg border border-border bg-card p-5 shadow-xs">
              <header className="mb-3 flex items-start justify-between">
                <div>
                  <div className="text-overline">{c.label}</div>
                  <div className="mt-1 flex items-baseline gap-2">
                    <span className="text-tabular text-[22px] font-semibold leading-none tracking-tight text-foreground">
                      {cur}
                    </span>
                    <span className="text-tabular text-[12px] text-muted-foreground">{c.unit.trim()}</span>
                    <span className={`text-tabular text-[11.5px] ${delta > 0 ? "text-success" : delta < 0 ? "text-critical" : "text-muted-foreground"}`}>
                      {delta > 0 ? "▲" : delta < 0 ? "▼" : "—"} {Math.abs(delta).toFixed(2)}
                    </span>
                  </div>
                </div>
                <div className="text-tabular text-[10.5px] uppercase tracking-wider text-muted-foreground">
                  {target} · {range}
                </div>
              </header>
              {pts.length === 0 ? (
                <div className="flex h-[200px] items-center justify-center rounded-md border border-dashed border-border text-center text-[12px] text-muted-foreground">
                  No telemetry series data received from swarm yet. Waiting for live updates...
                </div>
              ) : c.bars ? (
                <ProBars data={pts} unit={c.unit} tone={c.tone} height={200} />
              ) : (
                <ProChart data={pts} unit={c.unit} tone={c.tone} height={200} domain={c.domain as any} />
              )}
              <footer className="mt-3 grid grid-cols-4 gap-3 border-t border-border pt-3 text-[11px]">
                <Stat label="min" value={pts.length > 0 ? Math.min(...pts.map((d) => d.v)).toFixed(1) : "—"} />
                <Stat label="max" value={pts.length > 0 ? Math.max(...pts.map((d) => d.v)).toFixed(1) : "—"} />
                <Stat label="mean" value={pts.length > 0 ? (pts.reduce((a, d) => a + d.v, 0) / pts.length).toFixed(1) : "—"} />
                <Stat label="samples" value={pts.length.toString()} />
              </footer>
            </section>
          );
        })}
      </div>
    </AppShell>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className="mt-0.5 text-tabular text-[13px] font-medium text-foreground">{value}</div>
    </div>
  );
}
