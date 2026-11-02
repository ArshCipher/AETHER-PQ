import { createFileRoute } from "@tanstack/react-router";
import { AppShell } from "@/components/app-shell";
import { useWebSocketContext } from "@/components/websocket-provider";
import { useState, useEffect, useRef } from "react";
import {
  Play, Terminal, Database, Shield, Server, FileText,
  ChevronRight, Activity, Info, Download, Film, Image,
  HardDrive, CheckCircle, Loader2, FolderOpen, FileCode,
  Binary, Search, RefreshCw,
} from "lucide-react";

export const Route = createFileRoute("/query")({
  component: QueryComponent,
});

const QUERY_TYPES = [
  { value: "1", label: "Flight Mission Logs", icon: FileText, desc: "Real-time altitude, yaw, coordinate, CPU/memory log telemetry" },
  { value: "2", label: "ACPE Policy State", icon: Shield, desc: "Symmetric key state, battery level, operational constraints, RSSI" },
  { value: "3", label: "Dynamic Storage Snapshot", icon: Database, desc: "List directory structure and sizing of companion file system" },
  { value: "4", label: "Read Config File", icon: Server, desc: "Fetch local JSON configuration entries from board storage" },
];

interface DiskFile {
  name: string;
  size: string;
  type: string;
  path: string;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function fileIcon(type: string) {
  if (type === "video") return <Film className="h-8 w-8 text-violet-400" />;
  if (type === "image") return <Image className="h-8 w-8 text-emerald-400" />;
  if (type === "log")   return <FileText className="h-8 w-8 text-amber-400" />;
  if (type === "config") return <FileCode className="h-8 w-8 text-sky-400" />;
  if (type === "binary") return <Binary className="h-8 w-8 text-rose-400" />;
  return <HardDrive className="h-8 w-8 text-muted-foreground" />;
}

function fileColorClass(type: string): string {
  if (type === "video")  return "border-violet-500/30 hover:border-violet-500/60 hover:bg-violet-500/5";
  if (type === "image")  return "border-emerald-500/30 hover:border-emerald-500/60 hover:bg-emerald-500/5";
  if (type === "log")    return "border-amber-500/30 hover:border-amber-500/60 hover:bg-amber-500/5";
  if (type === "config") return "border-sky-500/30 hover:border-sky-500/60 hover:bg-sky-500/5";
  if (type === "binary") return "border-rose-500/30 hover:border-rose-500/60 hover:bg-rose-500/5";
  return "border-border hover:bg-surface-2";
}

function QueryComponent() {
  const { data, sendCommand, authState } = useWebSocketContext();
  const userRole = authState?.role || "Viewer";

  // ── Secure Query state ─────────────────────────────────
  const [selectedUav, setSelectedUav] = useState("UAV-001");
  const [queryType, setQueryType] = useState("1");
  const [pathOrKey, setPathOrKey] = useState("/home/uav/uav_logs/flight.log");
  const [consoleLogs, setConsoleLogs] = useState<string[]>([
    "AETHER-PQ Secure Query Terminal Ready.",
    "Select a target UAV and request parameters to fetch dynamic data over the post-quantum session tunnel.",
  ]);
  const [isQuerying, setIsQuerying] = useState(false);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // ── File Browser state ─────────────────────────────────
  const [browseUav, setBrowseUav] = useState("UAV-001");
  const [browsePath, setBrowsePath] = useState("/home/uav/uav_media");
  const [isBrowsing, setIsBrowsing] = useState(false);
  const [diskFiles, setDiskFiles] = useState<DiskFile[]>([]);
  const [browseError, setBrowseError] = useState("");

  // ── File Transfer state ────────────────────────────────
  const [transferUav, setTransferUav] = useState("UAV-001");
  const [isPulling, setIsPulling] = useState(false);
  const [pullingFile, setPullingFile] = useState("");
  const [pullDone, setPullDone] = useState(false);
  const [pullBytesTotal, setPullBytesTotal] = useState(0);
  const [pullChunks, setPullChunks] = useState(0);
  const [pulledFilename, setPulledFilename] = useState("received_file.bin");
  const GATEWAY_DOWNLOAD_URL = typeof window !== "undefined" ? `${window.location.protocol}//${window.location.hostname}:3001` : "http://localhost:3001";

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [consoleLogs]);

  // Handle query responses
  useEffect(() => {
    if (data?.queryResult) {
      const qr = data.queryResult;
      if (qr.id === selectedUav && String(qr.queryType) === queryType) {
        setIsQuerying(false);
        setConsoleLogs((prev) => [
          ...prev,
          `[SUCCESS] Secure response verified from ${qr.id} (Epoch e-${data.treekem?.epoch || 1})`,
          `[DECRYPTED] Payload data:`,
          `  ${qr.result}`,
          "--------------------------------------------------------------------------------",
        ]);
      }
    }
  }, [data?.queryResult]);

  // Handle file list response
  useEffect(() => {
    if (data?.fileList) {
      setIsBrowsing(false);
      setBrowseError("");
      if (!data.fileList.files || data.fileList.files.length === 0) {
        setBrowseError("Directory is empty or no accessible files found.");
        setDiskFiles([]);
      } else {
        setDiskFiles(data.fileList.files as DiskFile[]);
        setConsoleLogs((prev) => [
          ...prev,
          `[BROWSE] File listing received from ${data.fileList.id} — ${data.fileList.files.length} file(s) found`,
          "--------------------------------------------------------------------------------",
        ]);
      }
      // Sync the transfer UAV to match the browse UAV
      setTransferUav(data.fileList.id);
    }
  }, [data?.fileList]);

  // Handle file transfer progress
  useEffect(() => {
    if (data?.fileTransferProgress) {
      const p = data.fileTransferProgress;
      setPullBytesTotal(p.bytes ?? 0);
      setPullChunks((p.chunk ?? 0) + 1);
    }
  }, [data?.fileTransferProgress]);

  // Handle file transfer complete
  useEffect(() => {
    if (data?.fileTransferComplete) {
      const c = data.fileTransferComplete;
      setPullBytesTotal(c.bytes ?? 0);
      setPulledFilename(c.filename ?? "received_file.bin");
      setIsPulling(false);
      setPullDone(true);
      setConsoleLogs((prev) => [
        ...prev,
        `[FILE TRANSFER] ✓ ${c.filename} received — ${formatBytes(c.bytes)} — AES-GCM verified`,
        "  File is ready to download from the gateway.",
        "--------------------------------------------------------------------------------",
      ]);
    }
  }, [data?.fileTransferComplete]);

  const handleQuery = () => {
    if (userRole === "Viewer") {
      setConsoleLogs((prev) => [...prev, "[ACCESS DENIED] Viewer role lacks QueryUAV permission."]);
      return;
    }
    setIsQuerying(true);
    setConsoleLogs((prev) => [
      ...prev,
      `[COMMAND] Initiating secure query on ${selectedUav}...`,
      `  Protocol: COMMAND (ID: 3)`,
      `  Session Key: ML-KEM Ephemeral / AES-256-GCM`,
      `  Query Type: ${QUERY_TYPES.find((q) => q.value === queryType)?.label}`,
      `  Parameters: ${pathOrKey || "default"}`,
    ]);
    sendCommand("query_uav", { id: selectedUav, queryType: parseInt(queryType, 10), pathOrKey });
    setTimeout(() => {
      setIsQuerying((cur) => {
        if (cur) {
          setConsoleLogs((prev) => [...prev, `[TIMEOUT] No response from ${selectedUav}. Node may be offline.`]);
          return false;
        }
        return cur;
      });
    }, 5000);
  };

  const handleBrowse = () => {
    if (userRole === "Viewer") {
      setBrowseError("Access Denied: Viewer role lacks ListUAVFiles permission.");
      return;
    }
    setDiskFiles([]);
    setBrowseError("");
    setIsBrowsing(true);
    setPullDone(false);
    setConsoleLogs((prev) => [
      ...prev,
      `[BROWSE] Requesting disk listing from ${browseUav} at ${browsePath}...`,
    ]);
    sendCommand("query_uav", { id: browseUav, queryType: 5, pathOrKey: browsePath });
    setTimeout(() => {
      setIsBrowsing((cur) => {
        if (cur) {
          setBrowseError("No response. Check that the UAV node is online and the path exists.");
          setConsoleLogs((prev) => [...prev, `[TIMEOUT] No file listing received from ${browseUav}.`]);
          return false;
        }
        return cur;
      });
    }, 8000);
  };

  const handleTransferFile = (file: DiskFile) => {
    if (userRole !== "Admin" && userRole !== "Operator") {
      setConsoleLogs((prev) => [...prev, `[ACCESS DENIED] Role ${userRole} lacks RetrieveUAVFiles permission.`]);
      return;
    }
    setPullDone(false);
    setPullBytesTotal(0);
    setPullChunks(0);
    setIsPulling(true);
    setPullingFile(file.name);
    setConsoleLogs((prev) => [
      ...prev,
      `[FILE PULL] Requesting encrypted transfer of ${file.name} from ${transferUav}...`,
      `  Size: ${formatBytes(parseInt(file.size, 10))}  Type: ${file.type}`,
      `  Path: ${file.path}`,
      `  Transfer: Chunked AES-256-GCM · ML-KEM session`,
    ]);
    sendCommand("send_file", { id: transferUav, filepath: file.path });
    setTimeout(() => {
      setIsPulling((cur) => {
        if (cur) {
          setConsoleLogs((prev) => [...prev, `[TIMEOUT] No file data received. Check UAV path or connectivity.`]);
          return false;
        }
        return cur;
      });
    }, 15000);
  };



  const onlineUavs = data?.fleet?.filter((u: any) => u.status === "nominal") || [];
  const uavOptions = onlineUavs.length > 0 ? onlineUavs : [
    { id: "UAV-001", callsign: "AETHER-001" },
    { id: "UAV-002", callsign: "AETHER-002" },
    { id: "UAV-003", callsign: "AETHER-003" },
    { id: "UAV-004", callsign: "AETHER-004" },
  ];

  return (
    <AppShell
      eyebrow="Diagnostics · Swarm"
      title="On-Demand Secure Query"
      breadcrumbs={[{ label: "Diagnostics", to: "/logs" }, { label: "On-Demand Query" }]}
    >
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">

        {/* ── Left column: Query + Browse controls ── */}
        <div className="flex flex-col gap-5 lg:col-span-1">

          {/* Secure Query card */}
          <div className="card-glass border border-border bg-surface-1 p-5 rounded-xl flex flex-col gap-4">
            <div>
              <h3 className="text-[15px] font-semibold text-foreground flex items-center gap-1.5">
                <Shield className="h-4 w-4 text-primary" />
                Secure Query
              </h3>
              <p className="text-[12px] text-muted-foreground mt-1">Pull runtime values over the PQC session.</p>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="uav-select" className="text-[12px] font-medium text-foreground">Target Node</label>
              <select id="uav-select" value={selectedUav} onChange={(e) => setSelectedUav(e.target.value)}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-[13px] text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring">
                {uavOptions.map((u: any) => <option key={u.id} value={u.id}>{u.callsign} ({u.id})</option>)}
              </select>
            </div>

            <div className="grid grid-cols-1 gap-1.5">
              {QUERY_TYPES.map((q) => {
                const Icon = q.icon;
                const active = queryType === q.value;
                return (
                  <button key={q.value} onClick={() => {
                    setQueryType(q.value);
                    if (q.value === "1") setPathOrKey("/home/uav/uav_logs/flight.log");
                    else if (q.value === "2") setPathOrKey("acpe.policy");
                    else if (q.value === "3") setPathOrKey("/home/uav/");
                    else if (q.value === "4") setPathOrKey("/home/uav/uav_logs/config.json");
                  }}
                    className={`flex items-start gap-2.5 rounded-lg border p-2.5 text-left transition-all cursor-pointer ${active ? "border-primary/50 bg-primary-muted/20" : "border-border bg-background hover:bg-surface-2 text-muted-foreground"}`}
                  >
                    <Icon className={`mt-0.5 h-4 w-4 ${active ? "text-primary" : "text-muted-foreground"}`} />
                    <div>
                      <div className="text-[12.5px] font-medium text-foreground">{q.label}</div>
                      <div className="text-[10.5px] text-muted-foreground leading-tight mt-0.5">{q.desc}</div>
                    </div>
                  </button>
                );
              })}
            </div>

            <input id="path-input" type="text" value={pathOrKey} onChange={(e) => setPathOrKey(e.target.value)}
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-[13px] text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring font-mono" />

            <button onClick={handleQuery} disabled={isQuerying || userRole === "Viewer"}
              className="w-full flex items-center justify-center gap-1.5 rounded-md bg-primary py-2 text-[13px] font-medium text-primary-foreground hover:opacity-90 disabled:opacity-50 cursor-pointer transition-opacity">
              {isQuerying ? <Activity className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              {userRole === "Viewer" ? "Query Denied (Viewer)" : isQuerying ? "Querying..." : "Execute Secure Query"}
            </button>
          </div>

          {/* Browse UAV Disk card */}
          <div className="card-glass border border-violet-500/20 bg-surface-1 p-5 rounded-xl flex flex-col gap-4">
            <div>
              <h3 className="text-[15px] font-semibold text-foreground flex items-center gap-1.5">
                <FolderOpen className="h-4 w-4 text-violet-400" />
                Browse UAV Disk
              </h3>
              <p className="text-[12px] text-muted-foreground mt-1">
                Securely list files on a UAV's storage over the ML-KEM session. Click any file to pull it encrypted.
              </p>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="browse-uav-select" className="text-[12px] font-medium text-foreground">Source Node</label>
              <select id="browse-uav-select" value={browseUav} onChange={(e) => setBrowseUav(e.target.value)}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-[13px] text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring">
                {uavOptions.map((u: any) => <option key={u.id} value={u.id}>{u.callsign} ({u.id})</option>)}
              </select>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="browse-path" className="text-[12px] font-medium text-foreground">Directory Path</label>
              <input id="browse-path" type="text" value={browsePath} onChange={(e) => setBrowsePath(e.target.value)}
                placeholder="/home/uav/uav_media"
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-[13px] text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring font-mono" />
              <div className="flex flex-wrap gap-1.5">
                {["/home/uav/uav_media", "/home/uav/uav_logs"].map((p) => (
                  <button key={p} onClick={() => setBrowsePath(p)}
                    className="text-[10px] px-2 py-0.5 rounded border border-border bg-background hover:bg-surface-2 text-muted-foreground font-mono cursor-pointer transition-colors">
                    {p.split("/").pop()}
                  </button>
                ))}
              </div>
            </div>

            <button onClick={handleBrowse} disabled={isBrowsing || userRole === "Viewer"} id="browse-disk-btn"
              className="w-full flex items-center justify-center gap-1.5 rounded-md border border-violet-500/50 bg-violet-500/10 hover:bg-violet-500/20 py-2 text-[13px] font-medium text-violet-300 transition-all disabled:opacity-50 cursor-pointer">
              {isBrowsing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
              {userRole === "Viewer" ? "Browse Denied (Viewer)" : isBrowsing ? "Listing files over PQC link..." : "Browse Disk"}
            </button>
          </div>
        </div>

        {/* ── Right column: File grid + Terminal ── */}
        <div className="flex flex-col gap-5 lg:col-span-2">

          {/* File Browser Grid */}
          {(diskFiles.length > 0 || browseError || isBrowsing) && (
            <div className="card-glass border border-border bg-surface-1 p-5 rounded-xl">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-[15px] font-semibold text-foreground flex items-center gap-1.5">
                  <FolderOpen className="h-4 w-4 text-violet-400" />
                  {diskFiles.length > 0 ? `${diskFiles.length} file${diskFiles.length !== 1 ? "s" : ""} on ${transferUav}` : "UAV File Browser"}
                </h3>
                {diskFiles.length > 0 && (
                  <button onClick={handleBrowse} disabled={isBrowsing}
                    className="flex items-center gap-1 rounded border border-border bg-background px-2.5 py-1 text-[11px] font-medium text-muted-foreground hover:bg-surface-2 cursor-pointer">
                    <RefreshCw className="h-3 w-3" />
                    Refresh
                  </button>
                )}
              </div>

              {isBrowsing && (
                <div className="flex items-center gap-3 text-[13px] text-muted-foreground py-8 justify-center">
                  <Loader2 className="h-5 w-5 animate-spin text-violet-400" />
                  Fetching disk listing over encrypted session...
                </div>
              )}

              {browseError && !isBrowsing && (
                <div className="text-[13px] text-destructive py-4 text-center">{browseError}</div>
              )}

              {diskFiles.length > 0 && !isBrowsing && (
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                  {diskFiles.map((file) => {
                    const isThisTransferring = isPulling && pullingFile === file.name;
                    const isThisDone = pullDone && pullingFile === file.name;
                    return (
                      <button
                        key={file.name}
                        onClick={() => !isPulling && (userRole === "Admin" || userRole === "Operator") && handleTransferFile(file)}
                        disabled={isPulling || (userRole !== "Admin" && userRole !== "Operator")}
                        className={`relative flex flex-col items-center gap-2 rounded-xl border p-4 text-center transition-all ${userRole !== "Admin" && userRole !== "Operator" ? "opacity-50 cursor-not-allowed border-dashed bg-surface-2" : "cursor-pointer"} disabled:opacity-50 ${fileColorClass(file.type)} ${isThisTransferring ? "ring-2 ring-cyan-400/50" : ""}`}
                      >
                        {isThisTransferring ? (
                          <Loader2 className="h-8 w-8 text-cyan-400 animate-spin" />
                        ) : (
                          fileIcon(file.type)
                        )}
                        <div className="w-full">
                          <div className="text-[11.5px] font-medium text-foreground truncate w-full" title={file.name}>
                            {file.name}
                          </div>
                          <div className="text-[10px] text-muted-foreground mt-0.5">
                            {formatBytes(parseInt(file.size, 10))} · {file.type}
                          </div>
                        </div>
                        {isThisTransferring && (
                          <div className="absolute inset-0 rounded-xl bg-cyan-500/5 flex items-end p-2">
                            <div className="w-full">
                              <div className="h-1 rounded-full bg-surface-2 overflow-hidden">
                                <div className="h-full bg-cyan-400 rounded-full" style={{ width: "40%", animation: "xfer-slide 1.2s ease-in-out infinite" }} />
                              </div>
                              <div className="text-[9px] text-cyan-400 mt-1 font-mono">{formatBytes(pullBytesTotal)} · {pullChunks} chunks</div>
                            </div>
                          </div>
                        )}
                      </button>
                    );
                  })}
                </div>
              )}

              {/* Transfer complete download banner */}
              {pullDone && !isPulling && (
                <div className="mt-4 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-4 flex items-center justify-between gap-4">
                  <div className="flex items-center gap-2">
                    <CheckCircle className="h-5 w-5 text-emerald-400 shrink-0" />
                    <div>
                      <div className="text-[13px] font-semibold text-emerald-300">Transfer Complete</div>
                      <div className="text-[11px] text-muted-foreground font-mono">
                        {pulledFilename} · {formatBytes(pullBytesTotal)} · {pullChunks} chunks · AES-GCM verified
                      </div>
                    </div>
                  </div>
                  <a href={`${GATEWAY_DOWNLOAD_URL}/download/${pulledFilename}?name=${encodeURIComponent(pullingFile || "received_file.bin")}&token=${encodeURIComponent(localStorage.getItem("aether_session_token") || "")}`}
                     id="download-file-btn"
                     download={pullingFile || "received_file.bin"}
                     className="flex items-center gap-1.5 rounded-md bg-emerald-600 hover:bg-emerald-500 px-4 py-2 text-[12px] font-medium text-white transition-colors cursor-pointer shrink-0">
                    <Download className="h-3.5 w-3.5" />
                    Download
                  </a>
                </div>
              )}
            </div>
          )}

          {/* Terminal / Console card */}
          <div className="card-glass border border-border bg-surface-1 p-5 rounded-xl flex flex-col flex-1 min-h-[420px]">
            <div className="flex items-center justify-between border-b border-border pb-3 mb-4">
              <h3 className="text-[15px] font-semibold text-foreground flex items-center gap-1.5">
                <Terminal className="h-4 w-4 text-primary" />
                Decrypted Session Log
              </h3>
              <button onClick={() => setConsoleLogs(["Terminal cleared."])}
                className="rounded border border-border bg-background px-2.5 py-1 text-[11px] font-medium text-muted-foreground hover:bg-surface-2 cursor-pointer">
                Clear Log
              </button>
            </div>

            <div className="flex-1 bg-background/50 border border-border rounded-lg p-4 font-mono text-[12px] text-primary overflow-y-auto leading-relaxed flex flex-col justify-between max-h-[500px]">
              <div className="space-y-1.5 select-text">
                {consoleLogs.map((log, idx) => (
                  <div key={idx} className={
                    log.startsWith("[SUCCESS]") ? "text-emerald-400"
                    : log.startsWith("[FILE TRANSFER]") ? "text-cyan-300 font-semibold"
                    : log.startsWith("[FILE PULL]") ? "text-cyan-400"
                    : log.startsWith("[BROWSE]") ? "text-violet-400"
                    : log.startsWith("[DECRYPTED]") ? "text-cyan-400 font-bold"
                    : log.startsWith("[COMMAND]") ? "text-primary font-medium"
                    : log.startsWith("[TIMEOUT]") ? "text-destructive"
                    : "text-muted-foreground"
                  }>
                    {log.startsWith("  ") ? (
                      <span>{log}</span>
                    ) : (
                      <span className="flex items-start gap-1">
                        <ChevronRight className="h-3.5 w-3.5 shrink-0 mt-0.5 opacity-60" />
                        <span>{log}</span>
                      </span>
                    )}
                  </div>
                ))}
                <div ref={terminalEndRef} />
              </div>
              <div className="mt-4 border-t border-border/30 pt-3 text-[11px] text-muted-foreground flex items-center gap-1.5">
                <Info className="h-3.5 w-3.5" />
                <span>All data is decrypted on-the-fly using 256-bit AES-GCM session keys. No internet required.</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <style>{`
        @keyframes xfer-slide {
          0%   { margin-left: -40%; }
          60%  { margin-left: 100%; }
          100% { margin-left: 100%; }
        }
      `}</style>
    </AppShell>
  );
}
