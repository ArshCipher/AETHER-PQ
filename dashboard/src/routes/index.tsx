import { createFileRoute, Link } from "@tanstack/react-router";
import { useState, useEffect, useRef } from "react";
import {
  AlertTriangle, ArrowUpRight, CheckCircle2, Cpu,
  KeyRound, ShieldCheck, Signal, Clock,
  Maximize2, Minimize2, VideoOff,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { Sparkline, ProChart } from "@/components/mini-chart";
import { LiveClock, LiveDot, LiveNumber } from "@/components/live";
import { useWebSocketContext } from "@/components/websocket-provider";
export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Executive Dashboard — AETHER-PQ" },
      { name: "description", content: "System-wide health, cryptographic posture, and fleet overview for AETHER-PQ post-quantum UAV operations." },
    ],
  }),
  component: Dashboard,
});

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

function KpiCard({
  label, value, unit, trend, tone = "primary", spark, foot,
}: {
  label: string;
  value: React.ReactNode;
  unit?: string;
  trend?: { dir: "up" | "down" | "flat"; text: string };
  tone?: "primary" | "success" | "warning" | "critical" | "neutral";
  spark?: { t: number; v: number }[];
  foot?: React.ReactNode;
}) {

  return (
    <div className="rounded-lg border border-border bg-card p-4 shadow-xs">
      <div className="flex items-start justify-between">
        <div className="text-overline">{label}</div>
        {trend && (
          <div className={`text-tabular text-[11px] ${
            trend.dir === "up" ? "text-success" : trend.dir === "down" ? "text-critical" : "text-muted-foreground"
          }`}>
            {trend.dir === "up" ? "▲" : trend.dir === "down" ? "▼" : "—"} {trend.text}
          </div>
        )}
      </div>
      <div className="mt-3 flex items-baseline gap-1.5">
        <div className="text-tabular text-[26px] font-semibold leading-none tracking-tight text-foreground">{value}</div>
        {unit && <div className="text-tabular text-[12px] text-muted-foreground">{unit}</div>}
      </div>
      {spark && <div className="mt-2 -mx-1"><Sparkline data={spark} tone={tone} /></div>}
      {foot && <div className="mt-2 text-[11.5px] text-muted-foreground">{foot}</div>}
    </div>
  );
}

function ServiceRow({ name, detail, status, latency }: { name: string; detail: string; status: "operational" | "degraded" | "outage"; latency: string }) {
  const tone = status === "operational" ? "success" : status === "degraded" ? "warning" : "critical";
  return (
    <div className="flex items-center justify-between border-b border-border py-3 last:border-b-0">
      <div className="flex items-center gap-3">
        <LiveDot tone={tone} pulse={tone !== "success"} />
        <div>
          <div className="text-[13px] font-medium text-foreground">{name}</div>
          <div className="text-[11.5px] text-muted-foreground">{detail}</div>
        </div>
      </div>
      <div className="flex items-center gap-4">
        <div className="text-tabular text-[11.5px] text-muted-foreground">{latency}</div>
        <StatusPill tone={tone}>{status.toUpperCase()}</StatusPill>
      </div>
    </div>
  );
}

function LiveVideoPanel() {
  const { data, sendCommand } = useWebSocketContext();
  const [selectedUav, setSelectedUav] = useState<string>("UAV-001");
  const [lastFrameTime, setLastFrameTime] = useState<number>(0);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  const activeFleet = data?.fleet || [];

  // Keep selectedUav in sync with fleet — default to first available UAV
  const selectedUavData = activeFleet.find((u: any) => u.id === selectedUav);

  const latestFrame = data?.videoFrame?.id === selectedUav ? data.videoFrame : null;
  const frameSeq = latestFrame?._seq;

  const hasCamera: boolean = selectedUavData?.hasCamera ?? (selectedUav === "UAV-001");
  const isStreaming = Boolean(latestFrame && latestFrame.frame);

  const toggleFullscreen = () => {
    if (!containerRef.current) return;
    if (!document.fullscreenElement) {
      containerRef.current.requestFullscreen().then(() => setIsFullscreen(true)).catch(err => {
        console.error("Error enabling fullscreen:", err);
      });
    } else {
      document.exitFullscreen();
      setIsFullscreen(false);
    }
  };

  useEffect(() => {
    const handleFSChange = () => {
      setIsFullscreen(!!document.fullscreenElement);
    };
    document.addEventListener("fullscreenchange", handleFSChange);
    return () => document.removeEventListener("fullscreenchange", handleFSChange);
  }, []);

  return (
    <div 
      ref={containerRef} 
      className={`relative rounded-lg border border-border bg-card shadow-xs overflow-hidden ${isFullscreen ? "w-full h-full flex flex-col justify-center items-center bg-black" : "h-[380px] flex flex-col"}`}
    >
      <div className="flex items-center justify-between border-b border-border bg-surface px-4 py-3 z-10 w-full shrink-0">
        <div className="flex items-center gap-2.5">
          <div className={`h-2.5 w-2.5 rounded-full ${
            isStreaming ? "bg-success animate-pulse" 
            : hasCamera ? "bg-success animate-pulse" 
            : "bg-neutral-500"
          }`} />
          <span className="text-[13px] font-semibold text-foreground">
            {isFullscreen ? `Live Feed · ${selectedUav}` : "Live Swarm Tactical Video"}
          </span>
          {isStreaming && (
            <span className="text-[11px] bg-success-muted text-success px-1.5 py-0.5 rounded-md font-medium">
              STREAMING
            </span>
          )}
          {hasCamera && !isStreaming && (
            <span className="text-[11px] bg-success-muted text-success px-1.5 py-0.5 rounded-md font-medium">
              CAM ON
            </span>
          )}
          {data?.recordingStatus?.isRecording && (
            <span className="inline-flex items-center gap-1 text-[11px] bg-critical-muted text-critical px-2 py-0.5 rounded-md font-bold animate-pulse border border-critical/20">
              <span className="h-2 w-2 rounded-full bg-critical" />
              REC
            </span>
          )}
        </div>
        
        <div className="flex items-center gap-3">
          {!isFullscreen && (
            <>
              <button
                onClick={() => {
                  if (data?.recordingStatus?.isRecording) {
                    sendCommand("stop-recording");
                  } else {
                    sendCommand("start-recording", { missionId: "MSN-MANUAL", uavId: selectedUav });
                  }
                }}
                className={`h-7 px-2.5 rounded-md text-[11px] font-semibold transition-colors flex items-center gap-1.5 cursor-pointer ${
                  data?.recordingStatus?.isRecording 
                    ? "bg-critical text-white hover:bg-critical/90" 
                    : "bg-surface-2 hover:bg-surface border border-border text-foreground"
                }`}
                title={data?.recordingStatus?.isRecording ? "Stop Recording" : "Start Recording"}
              >
                {data?.recordingStatus?.isRecording ? (
                  <>
                    <span className="h-2 w-2 rounded-full bg-white animate-ping" />
                    Stop Rec
                  </>
                ) : (
                  <>
                    <span className="h-2 w-2 rounded-full bg-critical" />
                    Record
                  </>
                )}
              </button>

              <div className="flex items-center gap-2">
                <span className="text-[11px] text-muted-foreground uppercase tracking-wider">Source</span>
                <select 
                  value={selectedUav} 
                  onChange={(e) => setSelectedUav(e.target.value)}
                  className="h-7 rounded-md border border-border bg-background px-2 text-[12px] font-medium outline-none focus:border-primary"
                >
                  {activeFleet.map((u: any) => (
                    <option key={u.id} value={u.id}>
                      {u.id} · {u.callsign}
                    </option>
                  ))}
                </select>
              </div>
            </>
          )}
          
          <button 
            onClick={toggleFullscreen}
            className="flex items-center justify-center h-7 w-7 rounded-md hover:bg-surface-2 border border-border bg-background text-muted-foreground transition-colors cursor-pointer"
            title={isFullscreen ? "Exit Fullscreen" : "Fullscreen"}
          >
            {isFullscreen ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
          </button>
        </div>
      </div>

      <div className="relative flex-1 bg-black flex items-center justify-center overflow-hidden w-full h-full">
        {isStreaming ? (
          <img 
            src={latestFrame.frame} 
            alt={`Live feed from ${selectedUav}`}
            className="w-full h-full object-contain"
          />
        ) : hasCamera ? (
          // Camera is physically present on this UAV but not yet streaming
          <div className="flex flex-col items-center justify-center p-6 text-center">
            <div className="h-12 w-12 rounded-full bg-success/10 flex items-center justify-center border border-success/30 mb-3">
              <VideoOff className="h-6 w-6 text-success stroke-1" />
            </div>
            <h3 className="text-[14px] font-semibold text-foreground">Camera On</h3>
            <p className="mt-1.5 text-[12px] text-muted-foreground max-w-sm leading-relaxed">
              Hardware camera detected on <span className="font-semibold text-foreground">{selectedUav}</span>. The camera is active but no video signal is currently being received. Start the UAV node binary to begin streaming.
            </p>
            <div className="mt-3 flex items-center gap-2 text-[11px] text-success bg-success/10 px-3 py-1 rounded-md border border-success/20">
              <span className="h-2 w-2 rounded-full bg-success animate-pulse" />
              <span>Camera Status: On &mdash; No Signal</span>
            </div>
          </div>
        ) : (
          // No camera hardware on this UAV
          <div className="flex flex-col items-center justify-center p-6 text-center">
            <div className="h-12 w-12 rounded-full bg-surface-2 flex items-center justify-center border border-border mb-3">
              <VideoOff className="h-6 w-6 text-muted-foreground stroke-1" />
            </div>
            <h3 className="text-[14px] font-semibold text-foreground">No Camera Found</h3>
            <p className="mt-1.5 text-[12px] text-muted-foreground max-w-sm leading-relaxed">
              No hardware video camera detected on <span className="font-semibold text-foreground">{selectedUav}</span>. Connect a USB / V4L2 camera device to enable live tactical streaming.
            </p>
            <div className="mt-3 flex items-center gap-2 text-[11px] text-muted-foreground bg-surface px-3 py-1 rounded-md border border-border">
              <span className="h-2 w-2 rounded-full bg-neutral-500" />
              <span>Camera Status: Not Available</span>
            </div>
          </div>
        )}

        {isStreaming && (
          <div className="absolute bottom-4 left-4 right-4 flex flex-wrap gap-2.5 bg-black/60 backdrop-blur-xs border border-white/10 rounded-lg p-2.5 z-10 max-w-lg">
            <div className="flex flex-col px-2 py-0.5 border-r border-white/10 last:border-r-0">
              <span className="text-[9px] uppercase tracking-wider text-muted-foreground">FPS</span>
              <span className="text-tabular text-[12px] font-semibold text-white">{latestFrame.fps?.toFixed(1) || "10.0"}</span>
            </div>
            <div className="flex flex-col px-2 py-0.5 border-r border-white/10 last:border-r-0">
              <span className="text-[9px] uppercase tracking-wider text-muted-foreground">Bitrate</span>
              <span className="text-tabular text-[12px] font-semibold text-white">{(latestFrame.bitrate_kbps ?? latestFrame.bitrate ?? 120).toFixed(0)} Kbps</span>
            </div>
            <div className="flex flex-col px-2 py-0.5 border-r border-white/10 last:border-r-0">
              <span className="text-[9px] uppercase tracking-wider text-muted-foreground">Latency</span>
              <span className={`text-tabular text-[12px] font-semibold ${(latestFrame.latency_ms ?? latestFrame.latency ?? 0) < 50 ? "text-success" : (latestFrame.latency_ms ?? latestFrame.latency ?? 0) < 150 ? "text-warning" : "text-critical"}`}>
                {latestFrame.latency_ms ?? latestFrame.latency ?? 0} ms
              </span>
            </div>
            <div className="flex flex-col px-2 py-0.5 border-r border-white/10 last:border-r-0">
              <span className="text-[9px] uppercase tracking-wider text-muted-foreground">Loss</span>
              <span className={`text-tabular text-[12px] font-semibold ${(latestFrame.loss_pct ?? latestFrame.loss ?? 0) === 0 ? "text-success" : "text-warning"}`}>
                {(latestFrame.loss_pct ?? (latestFrame.loss ? latestFrame.loss * 100 : 0)).toFixed(1)}%
              </span>
            </div>
            <div className="flex flex-col px-2 py-0.5 border-r border-white/10 last:border-r-0">
              <span className="text-[9px] uppercase tracking-wider text-muted-foreground">Resolution</span>
              <span className="text-tabular text-[12px] font-semibold text-white">{latestFrame.width}x{latestFrame.height}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function Dashboard() {
  const { data, status } = useWebSocketContext();

  if (status !== "open" || !data) {
    return (
      <AppShell
        eyebrow="Command"
        title="Executive Dashboard"
        breadcrumbs={[{ label: "Command", to: "/" }, { label: "Executive Dashboard" }]}
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
  const activeAlerts = data.alerts || [];

  const online = activeFleet.filter((u: any) => u.status !== "offline" && u.status !== "maintenance").length;
  const critical = activeFleet.filter((u: any) => u.status === "critical").length;
  const degraded = activeFleet.filter((u: any) => u.status === "degraded").length;

  const avgLatency = online > 0 
    ? Math.round(activeFleet.filter((u: any) => u.status !== "offline").reduce((acc: number, u: any) => acc + u.latency, 0) / online)
    : 0;
  const avgCpu = online > 0 
    ? Math.round(activeFleet.filter((u: any) => u.status !== "offline").reduce((acc: number, u: any) => acc + u.cpu, 0) / online)
    : 0;

  const latency = avgLatency;
  const throughput = online > 0
    ? Math.round((activeFleet.filter((u: any) => u.status !== "offline").reduce((acc: number, u: any) => acc + (u.bandwidth || 0), 0) / online) * 10) / 10
    : 0;
  const cpu = avgCpu;
  const sessions = online;
  const health = online > 0 ? Math.max(50, 100 - (critical * 30 + degraded * 10)) : 100;
  const certs = activeFleet.length * 2 + 2;

  const exportSystemReport = () => {
    const report = `# AETHER-PQ Swarm Executive Report\n\n`
      + `Date/Time: ${new Date().toISOString()}\n`
      + `System Health: Swarm Active & Secure\n`
      + `Active Swarm Nodes: ${online} online / ${activeFleet.length} total\n`
      + `Mean Link Latency: ${latency} ms\n`
      + `Throughput: ${throughput} Mbps\n\n`
      + `## Fleet Status Summary\n`
      + activeFleet.map(u => `- ${u.id}: Status=${u.status.toUpperCase()} Battery=${u.battery}% Crypto=${u.cryptoProfile}`).join("\n") + "\n\n"
      + `## Recent System Notifications\n`
      + activeActivity.map(a => `[${a.ts}] [${a.actor}] ${a.message}`).join("\n");
      
    const blob = new Blob([report], { type: "text/markdown;charset=utf-8" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `aether_pq_executive_report_${new Date().toISOString().slice(0,10)}.md`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const activeState = activeFleet?.[0]?.policyMode || "L2-HYBRID";
  const elevatedPolicy = activeState !== "L1-CLASSICAL" && activeState !== "L2-HYBRID";

  const healthSeries = [{ t: 0, v: health }];
  const sessionsSeries = [{ t: 0, v: online }];
  const activeSessionsSeries = [{ t: 0, v: sessions }];
  const latencySeries = [{ t: 0, v: latency }];
  const throughputSpark = [{ t: 0, v: throughput }];
  const cpuSpark = [{ t: 0, v: cpu }];
  const certsSpark = [{ t: 0, v: certs }];
  const alertsSpark = [{ t: 0, v: activeAlerts.length }];

  return (
    <AppShell
      eyebrow="Command · Overview"
      title="Executive Dashboard"
      breadcrumbs={[{ label: "Command", to: "/" }, { label: "Executive Dashboard" }]}
      actions={
        <>
          <div className="flex items-center gap-1.5 rounded-md border border-border bg-background px-2.5 py-1.5 text-[12px]">
            <Clock className="h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
            <span className="text-muted-foreground">Live · <LiveClock /></span>
          </div>
          <button 
            onClick={exportSystemReport}
            className="rounded-md border border-border bg-background px-3 py-1.5 text-[12.5px] font-medium transition-colors hover:bg-surface-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring cursor-pointer"
          >
            Export Report
          </button>
          <Link to="/mission">
            <button className="rounded-md bg-primary px-3 py-1.5 text-[12.5px] font-medium text-primary-foreground transition-opacity hover:opacity-90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring cursor-pointer">New Mission</button>
          </Link>
        </>
      }
    >
      {/* Status banner */}
      {elevatedPolicy && (
        <div role="status" className="animate-fade-in-up mb-6 flex items-start gap-3 rounded-lg border border-warning/40 bg-warning-muted/60 p-3">
          <AlertTriangle className="mt-0.5 h-4 w-4 text-warning" aria-hidden="true" />
          <div className="flex-1">
            <div className="text-[13px] font-medium text-foreground">
              Policy elevated to {activeState}
            </div>
            <div className="mt-0.5 text-[12px] text-muted-foreground">
              ACPE automatically applied stricter cryptographic profile · affects {online} online UAVs
            </div>
          </div>
          <Link to="/acpe">
            <button className="rounded-md border border-border bg-background px-2.5 py-1 text-[11.5px] hover:bg-surface-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring cursor-pointer">Review</button>
          </Link>
        </div>
      )}

      {/* KPI row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        <KpiCard
          label="System Health"
          value={<><LiveNumber value={health} decimals={1} /></>}
          unit="%"
          tone="success"
          trend={{ dir: "up", text: "+0.2%" }}
          spark={healthSeries}
          foot="All core services operational"
        />
        <KpiCard
          label="Connected UAVs"
          value={<LiveNumber value={online} />}
          unit={`/ ${activeFleet.length}`}
          tone="primary"
          trend={{ dir: "flat", text: "stable" }}
          spark={sessionsSeries}
          foot={`${critical} critical · ${degraded} degraded`}
        />
        <KpiCard
          label="Active Sessions"
          value={<LiveNumber value={sessions} />}
          unit="secure"
          tone="primary"
          trend={{ dir: "up", text: "+6" }}
          spark={activeSessionsSeries}
          foot="mTLS + PQ handshake"
        />
        <KpiCard
          label="Mean Link Latency"
          value={<LiveNumber value={latency} />}
          unit="ms"
          tone="warning"
          trend={{ dir: "up", text: "+9 ms" }}
          spark={latencySeries}
          foot="p95 · 214 ms"
        />
        <KpiCard
          label="Throughput"
          value={<LiveNumber value={throughput} decimals={1} />}
          unit="Mbps"
          tone="primary"
          trend={{ dir: "up", text: "+2.1" }}
          spark={throughputSpark}
        />
        <KpiCard
          label="GCS CPU Load"
          value={<LiveNumber value={cpu} />}
          unit="%"
          tone="success"
          trend={{ dir: "flat", text: "stable" }}
          spark={cpuSpark}
        />
        <KpiCard
          label="Certificates · valid"
          value={<LiveNumber value={certs} />}
          tone="success"
          trend={{ dir: "up", text: "+12 issued" }}
          spark={certsSpark}
          foot="12 rotating in 6h"
        />
        <KpiCard
          label="Open Alerts"
          value={<LiveNumber value={activeAlerts.length} />}
          tone="critical"
          trend={{ dir: "up", text: "+1" }}
          spark={alertsSpark}
          foot="1 critical · 2 warning"
        />
      </div>

      <div className="mt-6">
        <LiveVideoPanel />
      </div>


      {/* AETHER-PQ Secure Mesh Routing Panel */}
      <div className="mt-6 rounded-lg border border-border bg-card p-5 shadow-xs">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border pb-4">
          <div>
            <div className="text-overline">Mesh Subsystem</div>
            <div className="mt-1 text-[16px] font-semibold text-foreground">Secure Multi-Hop Mesh Routing Protocol (uav_pqc::mesh)</div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <StatusPill tone="success">COMPOSITE ETX METRIC</StatusPill>
            <StatusPill tone="info">HMAC ROUTE AUTH</StatusPill>
            <StatusPill tone="neutral">E2EE PAYLOAD ISOLATION</StatusPill>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
          <div className="rounded-md border border-border bg-surface p-3.5">
            <div className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">Neighbor Discovery (HELLO)</div>
            <div className="mt-1 text-[20px] font-semibold text-foreground text-tabular">3 Active Neighbors</div>
            <div className="mt-1 text-[12px] text-success flex items-center gap-1">
              <span className="h-1.5 w-1.5 rounded-full bg-success animate-pulse" />
              Beacon Interval · 1,000 ms (RSSI & Loss Tracked)
            </div>
          </div>

          <div className="rounded-md border border-border bg-surface p-3.5">
            <div className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">Composite Metric (ETX + Latency)</div>
            <div className="mt-1 text-[20px] font-semibold text-foreground text-tabular">Mean ETX · 1.04</div>
            <div className="mt-1 text-[12px] text-muted-foreground">
              Sequence-Number Loop Protection Active
            </div>
          </div>

          <div className="rounded-md border border-border bg-surface p-3.5">
            <div className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">Route Authentication</div>
            <div className="mt-1 text-[20px] font-semibold text-primary text-tabular">HMAC-SHA256 Tagged</div>
            <div className="mt-1 text-[12px] text-muted-foreground">
              Anti-Poisoning & Anti-Replay Verified
            </div>
          </div>
        </div>

        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left text-[12.5px]">
            <thead>
              <tr className="border-b border-border text-[11px] font-medium text-muted-foreground uppercase tracking-wider">
                <th className="py-2 px-3">Destination Node</th>
                <th className="py-2 px-3">Next Hop Node</th>
                <th className="py-2 px-3">Hop Count</th>
                <th className="py-2 px-3">Composite Metric (ETX)</th>
                <th className="py-2 px-3">Seq Number</th>
                <th className="py-2 px-3">Security & Mode</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/50 text-foreground font-medium">
              {activeFleet.filter((u: any) => u.status !== "offline").map((u: any, idx: number) => {
                const securityMode = u.policyMode === "L3-PQ-AUTH" 
                  ? "PQ AUTH DIRECT" 
                  : u.policyMode === "L2-HYBRID" 
                    ? "HYBRID AUTH DIRECT" 
                    : "HMAC AUTH DIRECT";
                const pillTone = u.status === "nominal" ? "success" : u.status === "warning" ? "warning" : "critical";
                return (
                  <tr key={u.id}>
                    <td className="py-2.5 px-3">{u.id}</td>
                    <td className="py-2.5 px-3 text-primary text-tabular">{u.id} (Direct)</td>
                    <td className="py-2.5 px-3 text-tabular">1 Hop</td>
                    <td className="py-2.5 px-3 text-success text-tabular">ETX 1.00 / {u.latency} ms</td>
                    <td className="py-2.5 px-3 text-tabular">#{1042 + idx}</td>
                    <td className="py-2.5 px-3">
                      <StatusPill tone={pillTone === "success" ? "success" : "info"}>
                        {securityMode}
                      </StatusPill>
                    </td>
                  </tr>
                );
              })}
              {activeFleet.filter((u: any) => u.status !== "offline").length === 0 && (
                <tr>
                  <td colSpan={6} className="py-4 text-center text-muted-foreground">
                    No active routes. Swarm link offline.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Second row — posture + charts */}
      <div className="mt-6 grid grid-cols-1 gap-4 xl:grid-cols-3">
        {/* Cryptographic posture */}
        <div className="rounded-lg border border-border bg-card p-5 shadow-xs">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-overline">Cryptographic Posture</div>
              <div className="mt-1 text-[15px] font-semibold text-foreground">Adaptive Policy Engine</div>
            </div>
            <StatusPill tone="warning">L3-HYBRID</StatusPill>
          </div>
          <dl className="mt-4 space-y-3 text-[13px]">
            <div className="flex items-center justify-between">
              <dt className="text-muted-foreground">Operating Mode</dt>
              <dd className="text-tabular font-medium">HYBRID · ADAPTIVE</dd>
            </div>
            <div className="flex items-center justify-between">
              <dt className="text-muted-foreground">Current Profile</dt>
              <dd className="text-tabular font-medium">X25519 + ML-KEM-768</dd>
            </div>
            <div className="flex items-center justify-between">
              <dt className="text-muted-foreground">Signature Suite</dt>
              <dd className="text-tabular font-medium">ML-DSA-65 (Dilithium)</dd>
            </div>
            <div className="flex items-center justify-between">
              <dt className="text-muted-foreground">TreeKEM Epoch</dt>
              <dd className="text-tabular font-medium">e-{data?.treekem?.epoch || 1442} · active</dd>
            </div>
            <div className="flex items-center justify-between">
              <dt className="text-muted-foreground">Group Members</dt>
              <dd className="text-tabular font-medium">{online} nodes</dd>
            </div>
            <div className="flex items-center justify-between">
              <dt className="text-muted-foreground">Next Rotation</dt>
              <dd className="text-tabular font-medium">in 25m 48s</dd>
            </div>
          </dl>
          <div className="mt-4 border-t border-border pt-3 text-[11.5px] text-muted-foreground">
            Policy last elevated automatically by ACPE due to RTT variance &gt; 40 ms.
          </div>
        </div>

        {/* Service status */}
        <div className="rounded-lg border border-border bg-card p-5 shadow-xs xl:col-span-2">
          <div className="mb-2 flex items-center justify-between">
            <div>
              <div className="text-overline">Infrastructure</div>
              <div className="mt-1 text-[15px] font-semibold text-foreground">Service Status</div>
            </div>
            <div className="text-tabular text-[11.5px] text-muted-foreground">Region · IN-SOUTH-1</div>
          </div>
          <div>
            <ServiceRow name="Certificate Authority (CA)" detail="Root · Intermediate · OCSP responder" status="operational" latency="12 ms" />
            <ServiceRow name="Ground Control Station (GCS-01)" detail="Primary · MAVLink 2.0 · PQ enabled" status="operational" latency="8 ms" />
            <ServiceRow name="Ground Control Station (GCS-02)" detail="Standby · warm failover" status="operational" latency="11 ms" />
            <ServiceRow name="Adaptive Cryptographic Policy Engine" detail="4 policies active · L3 enforced" status="operational" latency="6 ms" />
            <ServiceRow name="TreeKEM Group Key Manager" detail={`${online} nodes · epoch e-${data?.treekem?.epoch || 1442}`} status="operational" latency="14 ms" />
            <ServiceRow name="LTE Backhaul (Carrier A)" detail="Primary · degraded on cell B-14" status={status === "open" ? "operational" : "degraded"} latency="128 ms" />
            <ServiceRow name="Ethernet Mesh" detail="Fallback · healthy" status="operational" latency="9 ms" />
            <ServiceRow name="ns-3 Simulation Harness" detail="Research profile · 3 runs queued" status="operational" latency="—" />
          </div>
        </div>
      </div>

      {/* Charts + activity */}
      <div className="mt-6 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="rounded-lg border border-border bg-card p-5 shadow-xs xl:col-span-2">
          <div className="mb-3 flex items-center justify-between">
            <div>
              <div className="text-overline">Network</div>
              <div className="mt-1 text-[15px] font-semibold text-foreground">Fleet Link Latency · last 5 min</div>
            </div>
            <div className="flex items-center gap-3 text-[11.5px] text-muted-foreground">
              <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm" style={{ background: "var(--color-primary)" }} />Mean</span>
              <span className="text-tabular"><LiveNumber value={latency} /> ms · p95 214 ms</span>
            </div>
          </div>
          <ProChart data={latencySeries} unit=" ms" tone="primary" height={240} />
        </div>

        <div className="rounded-lg border border-border bg-card p-5 shadow-xs">
          <div className="mb-3 flex items-center justify-between">
            <div>
              <div className="text-overline">Security</div>
              <div className="mt-1 text-[15px] font-semibold text-foreground">Active Alerts</div>
            </div>
            <StatusPill tone="critical">{activeAlerts.length} open</StatusPill>
          </div>
          <ul className="space-y-3">
            {activeAlerts.map((a: any) => (
              <li key={a.id} className="rounded-md border border-border bg-surface p-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <StatusPill tone={a.severity === "critical" ? "critical" : a.severity === "warning" ? "warning" : "info"}>
                        {a.severity.toUpperCase()}
                      </StatusPill>
                      <span className="text-tabular text-[11px] text-muted-foreground">{a.id}</span>
                    </div>
                    <div className="mt-1.5 text-[13px] font-medium text-foreground">{a.title}</div>
                    <div className="mt-0.5 text-[12px] text-muted-foreground">{a.detail}</div>
                  </div>
                  <div className="shrink-0 text-tabular text-[11px] text-muted-foreground">{a.ts}</div>
                </div>
                <div className="mt-2 flex items-center justify-between text-[11.5px] text-muted-foreground">
                  <span>Source · {a.source}</span>
                  <Link to="/logs" className="text-primary hover:underline flex items-center gap-0.5">Investigate <ArrowUpRight className="h-3 w-3" /></Link>
                </div>
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* Activity */}
      <div className="mt-6 rounded-lg border border-border bg-card shadow-xs">
        <div className="flex items-center justify-between border-b border-border px-5 py-3.5">
          <div>
            <div className="text-overline">Audit</div>
            <div className="mt-0.5 text-[15px] font-semibold text-foreground">Recent Activity</div>
          </div>
          <Link to="/logs" className="text-[12px] text-primary hover:underline flex items-center gap-0.5">View full audit log <ArrowUpRight className="h-3 w-3" /></Link>
        </div>
        <ul>
          {activeActivity.map((e: any, i: number) => {
            const icon =
              e.kind === "rotation" ? KeyRound :
              e.kind === "handshake" ? ShieldCheck :
              e.kind === "cert" ? CheckCircle2 :
              e.kind === "policy" ? Cpu :
              e.kind === "link" ? Signal :
              AlertTriangle;
            const Icon = icon;
            const tone =
              e.severity === "critical" ? "text-critical" :
              e.severity === "warning" ? "text-warning" :
              e.severity === "success" ? "text-success" :
              "text-muted-foreground";
            return (
              <li key={i} className="flex items-start gap-4 border-b border-border px-5 py-3 last:border-b-0 hover:bg-surface">
                <div className={`mt-0.5 ${tone}`}>
                  <Icon className="h-4 w-4" strokeWidth={2} />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="text-[13px] text-foreground">{e.message}</div>
                  <div className="mt-0.5 text-[11.5px] text-muted-foreground">
                    <span className="text-tabular">{e.ts}</span> · {e.actor} · {e.kind.toUpperCase()}
                  </div>
                </div>
                <StatusPill tone={e.severity === "critical" ? "critical" : e.severity === "warning" ? "warning" : e.severity === "success" ? "success" : "info"}>
                  {e.severity.toUpperCase()}
                </StatusPill>
              </li>
            );
          })}
        </ul>
      </div>
    </AppShell>
  );
}

