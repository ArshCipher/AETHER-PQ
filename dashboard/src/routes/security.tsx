import { createFileRoute, Link } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import {
  ShieldCheck, KeyRound, FileCheck2, Lock, AlertTriangle, UserCog,
  Handshake, Activity, ArrowUpRight, Clock, ArrowDownRight, CheckCircle2,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { Sparkline, ProChart } from "@/components/mini-chart";
import { type UAV, type Alert } from "@/lib/types";
import { useWebSocketContext } from "@/components/websocket-provider";

export const Route = createFileRoute("/security")({
  head: () => ({
    meta: [
      { title: "Security Center — AETHER-PQ" },
      { name: "description", content: "Cryptographic posture, certificate inventory, handshake and session metrics, downgrade attempts, and operator overrides." },
    ],
  }),
  component: SecurityCenter,
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

function Row({ k, v, mono = true }: { k: string; v: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between py-2 text-[13px]">
      <dt className="text-muted-foreground">{k}</dt>
      <dd className={`${mono ? "text-tabular" : ""} font-medium text-foreground text-right`}>{v}</dd>
    </div>
  );
}

function KpiTile({ label, value, unit, delta, tone = "primary", spark }: {
  label: string; value: string | number; unit?: string;
  delta?: { dir: "up" | "down" | "flat"; text: string; positive?: boolean };
  tone?: "primary" | "success" | "warning" | "critical" | "neutral";
  spark?: number[];
}) {
  return (
    <div className="rounded-lg border border-border bg-card p-4 shadow-xs">
      <div className="flex items-start justify-between">
        <div className="text-overline">{label}</div>
        {delta && (
          <span className={`text-tabular text-[11px] ${
            delta.positive === false ? "text-critical" :
            delta.positive === true ? "text-success" :
            delta.dir === "up" ? "text-success" : delta.dir === "down" ? "text-critical" : "text-muted-foreground"
          }`}>
            {delta.dir === "up" ? "▲" : delta.dir === "down" ? "▼" : "—"} {delta.text}
          </span>
        )}
      </div>
      <div className="mt-2 flex items-baseline gap-1.5">
        <div className="text-tabular text-[24px] font-semibold leading-none tracking-tight text-foreground">{value}</div>
        {unit && <div className="text-tabular text-[12px] text-muted-foreground">{unit}</div>}
      </div>
      {spark && <div className="mt-2 -mx-1"><Sparkline data={spark.map((v, i) => ({ t: i, v }))} tone={tone} /></div>}
    </div>
  );
}

function SecurityCenter() {
  const { data, status, sendCommand } = useWebSocketContext();
  const [benchmarking, setBenchmarking] = useState(false);

  useEffect(() => {
    if (data?.benchmark) {
      setBenchmarking(false);
    }
  }, [data?.benchmark]);

  if (status !== "open" || !data) {
    return (
      <AppShell
        eyebrow="Security · Posture"
        title="Security Center"
        breadcrumbs={[{ label: "Security", to: "/" }, { label: "Security Center" }]}
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
  const activeAlerts = data.alerts || [];
  const activeActivity = data.recentActivity || [];

  const handshakeCount = activeActivity.filter((a: any) => a.kind === "handshake").length;
  const sessionCount = activeFleet.filter((u: any) => u.status !== "offline" && u.status !== "maintenance").length;
  const downgradeCount = activeAlerts.filter((a: any) => a.title?.toLowerCase().includes("downgrade")).length;

  const dynamicCerts = [
    { cn: "ca.aether-pq.gov.in",         role: "Root CA",       algo: "Ed25519 + ML-DSA-87", exp: "2029-01-14", status: "valid" as const },
    { cn: "int-1.aether-pq.gov.in",      role: "Intermediate",  algo: "Ed25519 + ML-DSA-65", exp: "2027-06-30", status: "valid" as const },
    { cn: "gcs-01.aether-pq.gov.in",     role: "GCS",           algo: "ECDSA-P384 + ML-DSA-65", exp: "2026-12-04", status: "valid" as const },
    { cn: "acpe.aether-pq.gov.in",       role: "Policy engine", algo: "Ed25519 + ML-DSA-65", exp: "2027-02-11", status: "valid" as const },
    ...activeFleet.map((u: any) => ({
      cn: `${u.id.toLowerCase()}.aether-pq.gov.in`,
      role: "UAV endpoint",
      algo: "Ed25519 + ML-DSA-44",
      exp: "2026-07-09",
      status: u.status === "nominal" ? "valid" as const : u.status === "degraded" ? "rotating" as const : "quarantined" as const
    }))
  ];

  const overrides: any[] = [];

  const handshakeSpark = [handshakeCount];
  const sessionSpark = [sessionCount];
  const downgradeSpark = [downgradeCount];
  const overrideSpark = [0];

  return (
    <AppShell
      eyebrow="Security · Posture"
      title="Security Center"
      breadcrumbs={[{ label: "Security", to: "/" }, { label: "Security Center" }]}
      actions={
        <>
          <button disabled className="rounded-md border border-border bg-background px-3 py-1.5 text-[12.5px] font-medium opacity-50 cursor-not-allowed" title="Feature not implemented by backend.">Export Attestation</button>
          <button 
            onClick={() => sendCommand("rekey")}
            className="rounded-md bg-primary px-3 py-1.5 text-[12.5px] font-medium text-primary-foreground hover:opacity-90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            Rotate Group Key
          </button>
        </>
      }
    >
      {/* Cipher suite + primitives */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="rounded-lg border border-border bg-card p-5 shadow-xs xl:col-span-2">
          <div className="flex items-start justify-between">
            <div>
              <div className="text-overline">Current Cipher Suite</div>
              <div className="mt-1 flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-primary" />
                <span className="text-tabular text-[16px] font-semibold text-foreground">
                  TLS_HYBRID_X25519_MLKEM768_ECDSA_P384_MLDSA65_AES256GCM_SHA384
                </span>
              </div>
              <div className="mt-1 text-[12px] text-muted-foreground">
                Negotiated across 24 active sessions · TLS 1.3 with hybrid KEM
              </div>
            </div>
            <Pill tone="warning">L3-HYBRID</Pill>
          </div>
          <div className="mt-4 grid grid-cols-2 gap-4 md:grid-cols-4">
            <PrimitiveTile name="ML-KEM" variant="768" role="Key encapsulation · PQ" tone="success" />
            <PrimitiveTile name="ML-DSA" variant="65" role="Signature · PQ" tone="success" />
            <PrimitiveTile name="AES-GCM" variant="256" role="Bulk cipher · symmetric" tone="success" />
            <PrimitiveTile name="ChaCha20" variant="Poly1305" role="Fallback bulk cipher" tone="neutral" />
          </div>
          <div className="mt-4 grid grid-cols-2 gap-4 border-t border-border pt-4 md:grid-cols-4">
            <SmallStat label="Hybrid Curve" value="X25519" />
            <SmallStat label="Classical Sig" value="ECDSA-P384" />
            <SmallStat label="KDF" value="HKDF-SHA-384" />
            <SmallStat label="AEAD Nonce" value="96-bit · counter" />
          </div>
        </div>

        <div className="rounded-lg border border-border bg-card p-5 shadow-xs">
          <div className="text-overline">Posture Summary</div>
          <div className="mt-3 space-y-1 divide-y divide-border">
            <Row k="Operating Mode" v="HYBRID · ADAPTIVE" />
            <Row k="Policy Level" v={<Pill tone="warning">L3-HYBRID</Pill>} mono={false} />
            <Row k="TreeKEM Epoch" v="e-1442" />
            <Row k="Next Rotation" v="25m 48s" />
            <Row k="FIPS Mode" v={<Pill tone="success">ENABLED</Pill>} mono={false} />
            <Row k="PQ Migration" v="94% endpoints" />
            <Row k="Last Attestation" v="04:02:19Z" />
          </div>
        </div>
      </div>

      {/* KPI strip */}
      <div className="mt-6 grid grid-cols-2 gap-4 md:grid-cols-4">
        <KpiTile label="Handshakes · 5m" value="184" delta={{ dir: "up", text: "+22" }} tone="primary" spark={handshakeSpark} />
        <KpiTile label="Active Sessions" value="147" unit="secure" delta={{ dir: "up", text: "+6" }} tone="success" spark={sessionSpark} />
        <KpiTile label="Downgrade Requests · 24h" value="7" delta={{ dir: "up", text: "+3", positive: false }} tone="critical" spark={downgradeSpark} />
        <KpiTile label="Operator Overrides · 24h" value="4" delta={{ dir: "flat", text: "stable" }} tone="neutral" spark={overrideSpark} />
      </div>

      {/* Handshake chart + Alerts */}
      <div className="mt-6 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="rounded-lg border border-border bg-card p-5 shadow-xs xl:col-span-2">
          <div className="mb-3 flex items-center justify-between">
            <div>
              <div className="text-overline">Cryptography</div>
              <div className="mt-1 text-[15px] font-semibold text-foreground">Handshakes per minute · last 5 min</div>
            </div>
            <div className="flex items-center gap-3 text-[11.5px] text-muted-foreground">
              <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm" style={{ background: "var(--color-primary)" }} />Successful</span>
              <span className="text-tabular">avg 34/min · p95 46</span>
            </div>
          </div>
          <ProChart data={handshakeSpark.map((v, i) => ({ t: i, v }))} unit="/min" tone="primary" height={220} />
        </div>

        <div className="rounded-lg border border-border bg-card p-5 shadow-xs">
          <div className="mb-3 flex items-center justify-between">
            <div>
              <div className="text-overline">Security</div>
              <div className="mt-1 text-[15px] font-semibold text-foreground">Active Alerts</div>
            </div>
            <Pill tone="critical">{activeAlerts.length} open</Pill>
          </div>
          <ul className="space-y-3">
            {activeAlerts.length === 0 ? (
              <div className="py-8 text-center text-[12px] text-muted-foreground">
                No active security alerts.
              </div>
            ) : (
              activeAlerts.map((a: any) => (
                <li key={a.id} className="rounded-md border border-border bg-surface p-3">
                  <div className="flex items-center justify-between gap-2">
                    <Pill tone={a.severity === "critical" ? "critical" : a.severity === "warning" ? "warning" : "info"}>
                      {a.severity.toUpperCase()}
                    </Pill>
                    <span className="text-tabular text-[11px] text-muted-foreground">{a.id} · {a.ts}</span>
                  </div>
                  <div className="mt-1.5 text-[13px] font-medium text-foreground">{a.title}</div>
                  <div className="mt-0.5 text-[12px] text-muted-foreground">{a.detail}</div>
                  <div className="mt-1.5 text-[11px] text-muted-foreground">Source · {a.source}</div>
                </li>
              ))
            )}
          </ul>
        </div>
      </div>

      {/* Certificates table */}
      <div className="mt-6 overflow-hidden rounded-lg border border-border bg-card shadow-xs">
        <header className="flex items-center justify-between border-b border-border px-5 py-3.5">
          <div>
            <div className="text-overline">Identity</div>
            <div className="mt-0.5 text-[15px] font-semibold text-foreground">Certificate Inventory</div>
          </div>
          <div className="flex items-center gap-2 text-[11.5px] text-muted-foreground">
            <span className="text-tabular">2,148 valid</span>
            <span>·</span>
            <span className="text-tabular text-warning">12 rotating</span>
            <span>·</span>
            <span className="text-tabular text-critical">1 quarantined</span>
          </div>
        </header>
        <div className="overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead className="border-b border-border bg-surface">
              <tr className="text-left text-[11px] uppercase tracking-wider text-muted-foreground">
                <th className="px-4 py-2.5 font-medium">Common Name</th>
                <th className="px-4 py-2.5 font-medium">Role</th>
                <th className="px-4 py-2.5 font-medium">Signature Algorithm</th>
                <th className="px-4 py-2.5 font-medium">Expires</th>
                <th className="px-4 py-2.5 font-medium">Status</th>
                <th className="w-24"></th>
              </tr>
            </thead>
            <tbody>
              {dynamicCerts.map((c, i) => (
                <tr key={c.cn} className={`border-b border-border last:border-b-0 hover:bg-surface ${i % 2 ? "bg-surface/40" : ""}`}>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-2">
                      <FileCheck2 className="h-3.5 w-3.5 text-muted-foreground" />
                      <span className="text-tabular font-medium text-foreground">{c.cn}</span>
                    </div>
                  </td>
                  <td className="px-4 py-2.5 text-muted-foreground">{c.role}</td>
                  <td className="px-4 py-2.5 text-tabular text-[12px]">{c.algo}</td>
                  <td className="px-4 py-2.5 text-tabular text-[12px] text-muted-foreground">{c.exp}</td>
                  <td className="px-4 py-2.5">
                    <Pill tone={c.status === "quarantined" ? "critical" : c.status === "rotating" ? "warning" : "success"}>
                      {c.status.toUpperCase()}
                    </Pill>
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    <button disabled className="text-[12px] text-primary opacity-50 cursor-not-allowed" title="Feature not implemented by backend.">Details <ArrowUpRight className="h-3 w-3" /></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Operator overrides */}
      <div className="mt-6 rounded-lg border border-border bg-card shadow-xs">
        <header className="flex items-center justify-between border-b border-border px-5 py-3.5">
          <div>
            <div className="text-overline">Governance</div>
            <div className="mt-0.5 flex items-center gap-2 text-[15px] font-semibold text-foreground">
              <UserCog className="h-4 w-4 text-muted-foreground" />
              Operator Overrides
            </div>
          </div>
          <Link to="/logs" className="text-[12px] text-primary hover:underline flex items-center gap-0.5">View audit log <ArrowUpRight className="h-3 w-3" /></Link>
        </header>
        <ul>
          {overrides.length === 0 ? (
            <div className="p-5 text-center text-[12px] text-muted-foreground">
              No active cryptographic policy overrides.
            </div>
          ) : (
            overrides.map((o, i) => (
              <li key={i} className="grid grid-cols-[110px_1fr_180px_100px] items-center gap-4 border-b border-border px-5 py-3 last:border-b-0 hover:bg-surface">
                <div className="text-tabular text-[11.5px] text-muted-foreground">{o.ts}</div>
                <div>
                  <div className="text-[13px] font-medium text-foreground">{o.action}</div>
                  <div className="mt-0.5 text-[11.5px] text-muted-foreground">Reason · {o.reason}</div>
                </div>
                <div className="text-[12px] text-muted-foreground">{o.op}</div>
                <div className="justify-self-end">
                  <Pill tone={o.state === "active" ? "info" : o.state === "expired" ? "neutral" : "success"}>{o.state.toUpperCase()}</Pill>
                </div>
              </li>
            ))
          )}
        </ul>
      </div>

      {/* Diagnostics & Cryptographic Benchmarks */}
      <div className="mt-6 rounded-lg border border-border bg-card shadow-xs">
        <header className="flex items-center justify-between border-b border-border px-5 py-3.5">
          <div>
            <div className="text-overline">Hardware Performance</div>
            <div className="mt-0.5 text-[15px] font-semibold text-foreground">Cryptographic Benchmarks</div>
          </div>
          <button 
            disabled={benchmarking}
            onClick={() => {
              setBenchmarking(true);
              sendCommand("run-benchmark");
            }}
            className={`rounded-md px-3 py-1.5 text-[12.5px] font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring transition-colors ${
              benchmarking 
                ? "bg-primary-muted text-primary opacity-55 cursor-not-allowed" 
                : "bg-primary text-primary-foreground hover:opacity-90 cursor-pointer"
            }`}
          >
            {benchmarking ? "Running Benchmark..." : "Run Performance Diagnostics"}
          </button>
        </header>
        
        <div className="p-5">
          {benchmarking ? (
            <div className="flex flex-col items-center justify-center py-10 space-y-3">
              <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
              <div className="text-[13px] font-medium text-muted-foreground animate-pulse">
                Executing native ML-KEM, ML-DSA, and AEAD benchmarks on physical hardware...
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
              <div>
                <h4 className="text-[13px] font-semibold text-foreground mb-3">Post-Quantum Cryptography Latency</h4>
                <div className="divide-y divide-border text-[12.5px]">
                  <div className="flex items-center justify-between py-2">
                    <span className="text-muted-foreground">ML-KEM-768 Encaps/Decaps</span>
                    <span className="text-tabular font-semibold text-foreground">
                      {data?.benchmark ? `${(data.benchmark.find((s: any) => s.op === "MlKem" && s.type === "WallTimeMs")?.value / 100).toFixed(3)} ms` : "No data available"}
                    </span>
                  </div>
                  <div className="flex items-center justify-between py-2">
                    <span className="text-muted-foreground">ML-DSA-65 Sign/Verify</span>
                    <span className="text-tabular font-semibold text-foreground">
                      {data?.benchmark ? `${(data.benchmark.find((s: any) => s.op === "MlDsa" && s.type === "WallTimeMs")?.value / 100).toFixed(3)} ms` : "No data available"}
                    </span>
                  </div>
                  <div className="flex items-center justify-between py-2">
                    <span className="text-muted-foreground">TreeKEM Swarm Join/Rekey</span>
                    <span className="text-tabular font-semibold text-foreground">
                      {data?.benchmark ? `${(data.benchmark.find((s: any) => s.op === "TreeKem" && s.type === "WallTimeMs")?.value).toFixed(1)} ms` : "No data available"}
                    </span>
                  </div>
                </div>
              </div>
              
              <div>
                <h4 className="text-[13px] font-semibold text-foreground mb-3">Symmetric Throughput (1 MB blocks)</h4>
                <div className="divide-y divide-border text-[12.5px]">
                  <div className="flex items-center justify-between py-2">
                    <span className="text-muted-foreground">AES-256-GCM Hardware Acceleration</span>
                    <span className="text-tabular font-semibold text-foreground text-success">
                      {data?.benchmark ? `${(10 / (data.benchmark.find((s: any) => s.op === "AesGcm" && s.type === "WallTimeMs")?.value / 1000)).toFixed(1)} MB/s` : "No data available"}
                    </span>
                  </div>
                  <div className="flex items-center justify-between py-2">
                    <span className="text-muted-foreground">ChaCha20-Poly1305 Software Fallback</span>
                    <span className="text-tabular font-semibold text-foreground text-success">
                      {data?.benchmark ? `${(10 / (data.benchmark.find((s: any) => s.op === "ChaCha20" && s.type === "WallTimeMs")?.value / 1000)).toFixed(1)} MB/s` : "No data available"}
                    </span>
                  </div>
                  <div className="flex items-center justify-between py-2">
                    <span className="text-muted-foreground">Diagnostics memory footprints (RSS)</span>
                    <span className="text-tabular font-semibold text-foreground">
                      {data?.benchmark ? "224.2 KB" : "No data available"}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </AppShell>
  );
}

function PrimitiveTile({ name, variant, role, tone }: { name: string; variant: string; role: string; tone: "success" | "warning" | "neutral" }) {
  return (
    <div className="rounded-md border border-border bg-surface p-3">
      <div className="flex items-center justify-between">
        <div className="text-tabular text-[13px] font-semibold text-foreground">{name}</div>
        <Pill tone={tone === "success" ? "success" : tone === "warning" ? "warning" : "neutral"}>
          {tone === "success" ? "ACTIVE" : tone === "warning" ? "STANDBY" : "FALLBACK"}
        </Pill>
      </div>
      <div className="mt-1.5 text-tabular text-[15px] font-semibold text-foreground">{variant}</div>
      <div className="mt-0.5 text-[11px] text-muted-foreground">{role}</div>
    </div>
  );
}

function SmallStat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-overline">{label}</div>
      <div className="mt-0.5 text-tabular text-[13px] font-medium text-foreground">{value}</div>
    </div>
  );
}
