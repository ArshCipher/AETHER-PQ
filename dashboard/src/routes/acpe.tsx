import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import {
  Cpu, ArrowRight, Battery, Signal, Radio, Activity, Shield, Route as RouteIcon,
  ChevronRight, ChevronDown, GaugeCircle, Wand2,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { Sparkline } from "@/components/mini-chart";
import { type UAV } from "@/lib/types";
import { useWebSocketContext } from "@/components/websocket-provider";

export const Route = createFileRoute("/acpe")({
  head: () => ({
    meta: [
      { title: "ACPE Policy Engine — AETHER-PQ" },
      { name: "description", content: "Adaptive Cryptographic Policy Engine — finite-state machine, decision inputs, thresholds, and full decision timeline with reasoning." },
    ],
  }),
  component: ACPE,
});

type PolicyState = "L1-CLASSICAL" | "L2-HYBRID" | "L3-HYBRID" | "L4-PQ-ONLY";

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

const STATES: { key: PolicyState; label: string; kem: string; sig: string; desc: string }[] = [
  { key: "L1-CLASSICAL", label: "L1", kem: "X25519",              sig: "ECDSA-P384",             desc: "Classical only · lab / trusted link" },
  { key: "L2-HYBRID",    label: "L2", kem: "X25519 + ML-KEM-512", sig: "ECDSA-P384 + ML-DSA-44", desc: "Baseline hybrid" },
  { key: "L3-HYBRID",    label: "L3", kem: "X25519 + ML-KEM-768", sig: "ECDSA-P384 + ML-DSA-65", desc: "Elevated · adaptive default" },
  { key: "L4-PQ-ONLY",   label: "L4", kem: "ML-KEM-1024",         sig: "ML-DSA-87",              desc: "Threat / high assurance" },
];

function ACPE() {
  const { data, status, sendCommand } = useWebSocketContext();

  if (status !== "open" || !data) {
    return (
      <AppShell
        eyebrow="Security · ACPE"
        title="Policy Engine"
        breadcrumbs={[{ label: "Security", to: "/" }, { label: "Policy Engine" }]}
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
  const activeState = activeFleet?.[0]?.policyMode || "L2-HYBRID";

  const nominalUavs = activeFleet.filter((u: any) => u.status === "nominal");
  const avgBattery = nominalUavs.length ? Math.round(nominalUavs.reduce((sum: number, u: any) => sum + u.battery, 0) / nominalUavs.length) : 0;
  const avgRssi = nominalUavs.length ? Math.round(nominalUavs.reduce((sum: number, u: any) => sum + u.rssi, 0) / nominalUavs.length) : 0;
  const avgSinr = nominalUavs.length ? Math.round((nominalUavs.reduce((sum: number, u: any) => sum + u.sinr, 0) / nominalUavs.length) * 10) / 10 : 0;
  const avgLatency = nominalUavs.length ? Math.round(nominalUavs.reduce((sum: number, u: any) => sum + u.latency, 0) / nominalUavs.length) : 0;
  const avgLoss = nominalUavs.length ? Math.round((nominalUavs.reduce((sum: number, u: any) => sum + (u.packetLoss || 0), 0) / nominalUavs.length) * 10) / 10 : 0;

  const liveInputs = [
    { icon: Battery,      key: "battery",   label: "Battery",     value: `${avgBattery}%`,  raw: avgBattery,   threshold: "≥ 20%",  status: avgBattery < 20 ? "critical" : avgBattery < 40 ? "warning" : "success" as const, weight: 0.10 },
    { icon: Signal,       key: "rssi",      label: "RSSI",        value: `${avgRssi} dBm`, raw: avgRssi, threshold: "≥ -85 dBm", status: avgRssi < -85 ? "critical" : avgRssi < -78 ? "warning" : "success" as const, weight: 0.12 },
    { icon: Radio,        key: "sinr",      label: "SINR",        value: `${avgSinr} dB`, raw: avgSinr, threshold: "≥ 8 dB", status: avgSinr < 8 ? "critical" : avgSinr < 12 ? "warning" : "success" as const, weight: 0.14 },
    { icon: Activity,     key: "loss",      label: "Packet Loss", value: `${avgLoss}%`, raw: avgLoss, threshold: "≤ 3%",   status: avgLoss > 3 ? "critical" : avgLoss > 2 ? "warning" : "success" as const, weight: 0.12 },
    { icon: GaugeCircle,  key: "latency",   label: "Latency",  value: `${avgLatency} ms`, raw: avgLatency, threshold: "≤ 200 ms", status: avgLatency > 200 ? "critical" : avgLatency > 150 ? "warning" : "success" as const, weight: 0.16 },
    { icon: Shield,       key: "threat",    label: "Threat Feed",      value: "NOMINAL", raw: 0, threshold: "GUARDED",  status: "success" as const, weight: 0.22 },
  ];

  const [expanded, setExpanded] = useState<number | null>(0);
  const [mode, setMode] = useState<"AUTO" | "MANUAL">("AUTO");
  const [selectedState, setSelectedState] = useState<PolicyState | null>(null);

  const handleApplyOverride = () => {
    if (mode === "MANUAL" && selectedState) {
      sendCommand("policy", { mode: selectedState });
    }
  };

  const policyEvents = activeActivity.filter((a: any) => a.kind === "policy");

  const scoreSeries = [
    { t: 0, v: avgLatency > 0 ? Math.round((avgLatency / 200) * 100) / 100 : 0 }
  ];

  return (
    <AppShell
      eyebrow="Security · Engine"
      title="Policy Engine"
      breadcrumbs={[{ label: "Security", to: "/" }, { label: "Policy Engine" }]}
    >
      {/* Current Enforcement */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="flex flex-col justify-between rounded-lg border border-border bg-card p-5 shadow-xs lg:col-span-2">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="text-overline">Enforcement State</div>
              <h3 className="mt-1.5 text-[22px] font-semibold tracking-tight text-foreground">
                {activeState}
              </h3>
              <p className="mt-1 text-[13px] text-muted-foreground">
                {STATES.find((s) => s.key === activeState)?.desc}
              </p>
            </div>
            <div className="rounded-full bg-primary/10 p-2 text-primary">
              <Shield className="h-6 w-6" />
            </div>
          </div>
          <div className="mt-6 grid grid-cols-3 gap-4 border-t border-border pt-4">
            <MiniStat label="KEM Primitive" value={STATES.find((s) => s.key === activeState)?.kem || "X25519"} />
            <MiniStat label="Auth Signatures" value={STATES.find((s) => s.key === activeState)?.sig || "ECDSA-P384"} />
            <MiniStat label="Evaluated Inputs" value={`${liveInputs.length} channels`} />
          </div>
        </div>

        <div className="rounded-lg border border-border bg-card p-5 shadow-xs">
          <div className="text-overline">Policy Rule Matrix</div>
          <div className="mt-3 space-y-2 text-[12.5px]">
            <div className="flex items-center justify-between border-b border-border pb-2">
              <span className="font-medium text-foreground">L1 Classical</span>
              <span className="text-muted-foreground">All inputs fully nominal</span>
            </div>
            <div className="flex items-center justify-between border-b border-border pb-2">
              <span className="font-medium text-foreground">L2 Hybrid</span>
              <span className="text-muted-foreground">RTT &gt; 120 ms or Loss &gt; 1%</span>
            </div>
            <div className="flex items-center justify-between border-b border-border pb-2">
              <span className="font-medium text-foreground">L3 Hybrid</span>
              <span className="text-muted-foreground">RTT &gt; 150 ms or Threat ELEVATED</span>
            </div>
            <div className="flex items-center justify-between pb-1">
              <span className="font-medium text-foreground">L4 PQ-Only</span>
              <span className="text-muted-foreground">Loss &gt; 3% or Threat CRITICAL</span>
            </div>
          </div>
        </div>
      </div>

      {/* Decision Panel */}
      <div className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Left: Inputs table */}
        <div className="rounded-lg border border-border bg-card p-5 shadow-xs lg:col-span-2">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <div className="text-overline">Monitoring</div>
              <h4 className="text-[15px] font-semibold text-foreground">Decision Metric Inputs</h4>
            </div>
            <Pill tone="success">LIVE EVALUATION</Pill>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-[13px]">
              <thead className="border-b border-border text-left text-[11px] uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="pb-2 font-medium">Metric</th>
                  <th className="pb-2 font-medium text-right">Swarm Mean</th>
                  <th className="pb-2 font-medium text-right">ACPE Target</th>
                  <th className="pb-2 font-medium text-right">Weight</th>
                  <th className="pb-2 font-medium text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {liveInputs.map((input) => {
                  const Icon = input.icon;
                  return (
                    <tr key={input.key} className="hover:bg-surface/50">
                      <td className="py-2.5">
                        <div className="flex items-center gap-2 font-medium text-foreground">
                          <Icon className="h-4 w-4 text-muted-foreground" />
                          <span>{input.label}</span>
                        </div>
                      </td>
                      <td className="py-2.5 text-right text-tabular font-semibold text-foreground">{input.value}</td>
                      <td className="py-2.5 text-right text-tabular text-muted-foreground">{input.threshold}</td>
                      <td className="py-2.5 text-right text-tabular text-muted-foreground">{(input.weight * 100).toFixed(0)}%</td>
                      <td className="py-2.5 text-right">
                        <Pill tone={input.status}>{input.status.toUpperCase()}</Pill>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right: composite & manual control */}
        <div className="rounded-lg border border-border bg-card p-5 shadow-xs">
          <div className="mb-4">
            <div className="text-overline">Configuration</div>
            <h4 className="text-[15px] font-semibold text-foreground">ACPE Operational Override</h4>
          </div>
          <div className="flex items-center gap-2 rounded-md border border-border bg-surface p-1 text-[12px] font-medium">
            <button
              onClick={() => setMode("AUTO")}
              className={`flex-1 rounded px-2.5 py-1.5 text-center transition-colors ${mode === "AUTO" ? "bg-background shadow-xs text-primary font-semibold" : "text-muted-foreground hover:bg-surface-2"}`}
            >
              Autonomous (ACPE)
            </button>
            <button
              onClick={() => setMode("MANUAL")}
              className={`flex-1 rounded px-2.5 py-1.5 text-center transition-colors ${mode === "MANUAL" ? "bg-background shadow-xs text-warning font-semibold" : "text-muted-foreground hover:bg-surface-2"}`}
            >
              Manual Override
            </button>
          </div>

          {mode === "MANUAL" ? (
            <div className="mt-4 space-y-4">
              <div>
                <label className="text-[11.5px] uppercase tracking-wider text-muted-foreground">Select Policy Level</label>
                <div className="mt-1.5 grid grid-cols-2 gap-2">
                  {STATES.map((s) => (
                    <button
                      key={s.key}
                      onClick={() => setSelectedState(s.key)}
                      className={`rounded-md border p-2 text-left transition-colors cursor-pointer ${
                        selectedState === s.key
                          ? "border-primary bg-primary/5 text-primary"
                          : "border-border bg-background hover:bg-surface-2"
                      }`}
                    >
                      <div className="text-[13px] font-semibold">{s.label}</div>
                      <div className="text-[10px] text-muted-foreground uppercase">{s.key.split("-")[1]}</div>
                    </button>
                  ))}
                </div>
              </div>
              <button
                onClick={handleApplyOverride}
                disabled={!selectedState}
                className="w-full rounded-md bg-primary py-2 text-[13px] font-medium text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Apply Cryptographic Override
              </button>
            </div>
          ) : (
            <div className="mt-4 space-y-4">
              <div className="divide-y divide-border text-[12.5px]">
                <ThresholdRow k="Congestion ceiling" v="≤ 0.75" />
                <ThresholdRow k="Threat elevation" v="score ≥ 0.60" />
                <ThresholdRow k="Composite → L3" v="score ≥ 0.65" />
                <ThresholdRow k="Composite → L4" v="score ≥ 0.85" />
                <ThresholdRow k="De-escalation window" v="12 min nominal" />
              </div>
              <div className="mt-4 rounded-md border border-border bg-surface p-3">
                <div className="text-overline mb-1.5">Composite score · 5 min</div>
                <Sparkline data={scoreSeries} tone="warning" height={48} />
                <div className="mt-1 flex items-center justify-between text-tabular text-[11px] text-muted-foreground">
                  <span>0.00</span><span className="text-foreground">now · {scoreSeries[0].v}</span><span>1.00</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Link Simulation & Netem Control */}
      <section className="mt-6 rounded-lg border border-border bg-card p-5 shadow-xs">
        <div className="mb-4">
          <div className="text-overline">Testing</div>
          <h4 className="text-[15px] font-semibold text-foreground">Swarm Link Simulation (Netem)</h4>
        </div>
        <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
          <div>
            <h5 className="text-[13px] font-semibold text-foreground mb-2">Simulate Network Delay</h5>
            <div className="flex gap-2">
              <button 
                onClick={() => sendCommand("net-simulation", { mode: "delay", delay: 100 })}
                className="flex-1 rounded border border-border bg-background py-1.5 text-[11px] font-semibold hover:bg-surface-2 cursor-pointer focus:outline-none"
              >
                +100ms
              </button>
              <button 
                onClick={() => sendCommand("net-simulation", { mode: "delay", delay: 200 })}
                className="flex-1 rounded border border-border bg-background py-1.5 text-[11px] font-semibold hover:bg-surface-2 cursor-pointer focus:outline-none"
              >
                +200ms
              </button>
              <button 
                onClick={() => sendCommand("net-simulation", { mode: "delay", delay: 300 })}
                className="flex-1 rounded border border-border bg-background py-1.5 text-[11px] font-semibold hover:bg-surface-2 cursor-pointer focus:outline-none"
              >
                +300ms
              </button>
            </div>
          </div>
          <div>
            <h5 className="text-[13px] font-semibold text-foreground mb-2">Simulate Packet Loss</h5>
            <div className="flex gap-2">
              <button 
                onClick={() => sendCommand("net-simulation", { mode: "loss", loss: 2 })}
                className="flex-1 rounded border border-border bg-background py-1.5 text-[11px] font-semibold hover:bg-surface-2 cursor-pointer focus:outline-none"
              >
                2%
              </button>
              <button 
                onClick={() => sendCommand("net-simulation", { mode: "loss", loss: 5 })}
                className="flex-1 rounded border border-border bg-background py-1.5 text-[11px] font-semibold hover:bg-surface-2 cursor-pointer focus:outline-none"
              >
                5%
              </button>
              <button 
                onClick={() => sendCommand("net-simulation", { mode: "loss", loss: 10 })}
                className="flex-1 rounded border border-border bg-background py-1.5 text-[11px] font-semibold hover:bg-surface-2 cursor-pointer focus:outline-none"
              >
                10%
              </button>
            </div>
          </div>
        </div>
        <button 
          onClick={() => sendCommand("net-simulation", { mode: "clear" })}
          className="w-full mt-4 rounded-md bg-destructive px-3 py-2 text-[12px] font-semibold text-destructive-foreground hover:opacity-90 cursor-pointer focus:outline-none"
        >
          Clear Link Degradation
        </button>
      </section>

      {/* Decision Timeline */}
      <section className="mt-6 rounded-lg border border-border bg-card shadow-xs">
        <header className="flex items-center justify-between border-b border-border px-5 py-3.5">
          <div>
            <div className="text-overline">Audit</div>
            <div className="mt-0.5 text-[15px] font-semibold text-foreground">Decision Timeline</div>
          </div>
          <div className="text-[11.5px] text-muted-foreground">last 24 hours · <span className="text-tabular text-foreground">{policyEvents.length}</span> transitions</div>
        </header>
        {policyEvents.length === 0 ? (
          <div className="p-5 text-center text-[12px] text-muted-foreground">
            No recent policy state transitions recorded.
          </div>
        ) : (
          <ol>
            {policyEvents.map((t: any, i: number) => {
              const open = expanded === i;
              return (
                <li key={i} className="border-b border-border last:border-b-0">
                  <button
                    onClick={() => setExpanded(open ? null : i)}
                    className="grid w-full grid-cols-[100px_1fr_28px] items-center gap-4 px-5 py-3.5 text-left hover:bg-surface"
                  >
                    <div className="text-tabular text-[11.5px] text-muted-foreground">{t.ts}</div>
                    <div className="text-[13px] font-medium text-foreground">{t.message}</div>
                    {open ? <ChevronDown className="h-4 w-4 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 text-muted-foreground" />}
                  </button>
                  {open && (
                    <div className="border-t border-border bg-surface px-5 py-3 text-[12.5px] text-muted-foreground">
                      Actor: <span className="font-medium text-foreground">{t.actor}</span>
                    </div>
                  )}
                </li>
              );
            })}
          </ol>
        )}
      </section>
    </AppShell>
  );
}

function MiniStat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-overline">{label}</div>
      <div className="mt-0.5 text-tabular text-[13px] font-medium text-foreground">{value}</div>
    </div>
  );
}

function ThresholdRow({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex items-center justify-between py-2">
      <span className="text-muted-foreground">{k}</span>
      <span className="text-tabular font-medium text-foreground">{v}</span>
    </div>
  );
}
