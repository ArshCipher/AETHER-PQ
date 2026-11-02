import { createFileRoute } from "@tanstack/react-router";
import { useState, useEffect, useRef } from "react";
import { AppShell } from "@/components/app-shell";
import { useWebSocketContext } from "@/components/websocket-provider";
import { 
  Play, Trash2, Download, Search, SlidersHorizontal, ShieldAlert,
  Video, Eye, Calendar, Clock, HardDrive, Maximize2, Minimize2,
  AlertCircle, Battery, Compass, Shield, Wifi, Gauge
} from "lucide-react";

export const Route = createFileRoute("/recordings")({
  component: RecordingsPage,
});

interface RecordingSummary {
  id: string;
  filename: string;
  missionId: string;
  uavId: string;
  startTime: number;
  durationMs: number;
  frameCount: number;
  fileSizeBytes: number;
  encrypted: boolean;
  thumbnail?: string;
}

interface RecordingFrame {
  ts: number;
  uavId: string;
  frame: string;
}

interface RecordingMetadata {
  ts: number;
  uavId: string;
  lat: number;
  lon: number;
  altitude: number;
  battery: number;
  voltage: number;
  speed: number;
  rssi: number;
  status: string;
  event?: string;
}

interface RecordingSession {
  id: string;
  filename: string;
  missionId: string;
  uavId: string;
  startTime: number;
  durationMs: number;
  frames: RecordingFrame[];
  metadata: RecordingMetadata[];
  encrypted: boolean;
}

function formatDuration(ms: number): string {
  const totalSecs = Math.floor(ms / 1000);
  const mins = Math.floor(totalSecs / 60);
  const secs = totalSecs % 60;
  return `${mins}:${secs.toString().padStart(2, "0")}`;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function formatDateTime(ts: number): string {
  return new Date(ts).toLocaleString();
}

const GATEWAY_URL = typeof window !== "undefined" ? `${window.location.protocol}//${window.location.hostname}:3001` : "http://localhost:3001";

function RecordingsPage() {
  const { sendCommand } = useWebSocketContext();
  const [recordings, setRecordings] = useState<RecordingSummary[]>([]);
  const [activeRecording, setActiveRecording] = useState<any>(null);
  const [autoRecord, setAutoRecord] = useState(true);
  const [storageUsed, setStorageUsed] = useState(0);
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState<"date" | "size" | "duration">("date");
  const [filterUav, setFilterUav] = useState("all");
  const [playingSession, setPlayingSession] = useState<RecordingSession | null>(null);
  const [loadingPlayId, setLoadingPlayId] = useState<string | null>(null);

  // Fetch recordings list on load
  const fetchRecordings = async () => {
    try {
      const res = await fetch(`${GATEWAY_URL}/api/recordings`);
      if (res.ok) {
        const data = await res.json();
        setRecordings(data.recordings || []);
        setStorageUsed(data.storageBytes || 0);
        setActiveRecording(data.activeRecording);
        setAutoRecord(data.autoRecordOnMissionStart ?? true);
      }
    } catch (err) {
      console.error("Failed to fetch recordings:", err);
    }
  };

  useEffect(() => {
    fetchRecordings();
    const interval = setInterval(fetchRecordings, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleToggleAutoRecord = (checked: boolean) => {
    setAutoRecord(checked);
    sendCommand("recording-config", {
      autoRecordOnMissionStart: checked
    });
  };

  const handleStartManualRecord = () => {
    sendCommand("start-recording", {
      missionId: "MSN-MANUAL",
      uavId: "UAV-001"
    });
    setTimeout(fetchRecordings, 500);
  };

  const handleStopManualRecord = () => {
    sendCommand("stop-recording");
    setTimeout(fetchRecordings, 500);
  };

  const handleDelete = async (id: string) => {
    if (confirm("Are you sure you want to permanently delete this mission recording?")) {
      try {
        const res = await fetch(`${GATEWAY_URL}/api/recordings/${id}`, { method: "DELETE" });
        if (res.ok) {
          fetchRecordings();
        }
      } catch (err) {
        console.error("Failed to delete recording:", err);
      }
    }
  };

  const handlePlay = async (id: string) => {
    setLoadingPlayId(id);
    try {
      const res = await fetch(`${GATEWAY_URL}/api/recordings/${id}`);
      if (res.ok) {
        const data = await res.json();
        setPlayingSession(data);
      }
    } catch (err) {
      console.error("Failed to load playback recording data:", err);
    } finally {
      setLoadingPlayId(null);
    }
  };

  const filteredRecordings = recordings
    .filter((r) => {
      const matchesSearch = r.missionId.toLowerCase().includes(search.toLowerCase()) || r.uavId.toLowerCase().includes(search.toLowerCase());
      const matchesUav = filterUav === "all" || r.uavId === filterUav;
      return matchesSearch && matchesUav;
    })
    .sort((a, b) => {
      if (sortBy === "size") return b.fileSizeBytes - a.fileSizeBytes;
      if (sortBy === "duration") return b.durationMs - a.durationMs;
      return b.startTime - a.startTime;
    });

  const uavIds = Array.from(new Set(recordings.map((r) => r.uavId)));

  return (
    <AppShell title="Mission Recordings" eyebrow="Diagnostics & Archive">
      <div className="space-y-6">
        {/* Top Control Bar */}
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          {/* Active Recording Status Panel */}
          <div className="rounded-lg border border-border bg-card p-4 shadow-xs">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className={`h-2.5 w-2.5 rounded-full ${activeRecording ? "bg-critical animate-pulse" : "bg-neutral-500"}`} />
                <h4 className="text-[13px] font-semibold text-foreground">Recording Engine Status</h4>
              </div>
              {activeRecording && (
                <span className="text-[10px] font-mono bg-critical-muted text-critical px-2 py-0.5 rounded-sm">
                  LIVE
                </span>
              )}
            </div>
            {activeRecording ? (
              <div className="mt-3 space-y-1 text-[12px]">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Active Mission:</span>
                  <span className="font-semibold">{activeRecording.missionId}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Source UAV:</span>
                  <span className="font-semibold">{activeRecording.uavId}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Frames Captured:</span>
                  <span className="font-semibold">{activeRecording.frameCount}</span>
                </div>
                <button
                  onClick={handleStopManualRecord}
                  className="mt-4 w-full h-8 rounded-md bg-critical text-white text-[12px] font-medium hover:bg-critical/90 transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
                >
                  <span className="h-2 w-2 rounded-full bg-white animate-ping" />
                  Stop Recording
                </button>
              </div>
            ) : (
              <div className="mt-3 text-[12px] text-muted-foreground space-y-4">
                <p>No active recording running. Stream recording will trigger automatically when a mission starts if configured.</p>
                <button
                  onClick={handleStartManualRecord}
                  className="w-full h-8 rounded-md bg-primary text-primary-foreground text-[12px] font-medium hover:bg-primary/90 transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
                >
                  <Play className="h-3 w-3 fill-current" />
                  Start Manual Recording
                </button>
              </div>
            )}
          </div>

          {/* Storage & Auto Record configuration */}
          <div className="rounded-lg border border-border bg-card p-4 shadow-xs flex flex-col justify-between">
            <div>
              <h4 className="text-[13px] font-semibold text-foreground flex items-center gap-1.5">
                <HardDrive className="h-4 w-4 text-muted-foreground" />
                Storage Archive Info
              </h4>
              <div className="mt-3 space-y-1.5 text-[12px]">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Used Storage:</span>
                  <span className="font-semibold">{formatBytes(storageUsed)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Total Recordings:</span>
                  <span className="font-semibold">{recordings.length} files</span>
                </div>
              </div>
            </div>
            <div className="mt-4 pt-3 border-t border-border flex items-center justify-between text-[12px]">
              <span className="text-muted-foreground font-medium">Auto-record on mission start</span>
              <label className="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  checked={autoRecord}
                  onChange={(e) => handleToggleAutoRecord(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-9 h-5 bg-border rounded-full peer peer-focus:ring-1 peer-focus:ring-primary peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-0.5 after:left-[2px] after:bg-white after:border-border after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-primary"></div>
              </label>
            </div>
          </div>

          {/* Search and Filters */}
          <div className="rounded-lg border border-border bg-card p-4 shadow-xs flex flex-col gap-3">
            <h4 className="text-[13px] font-semibold text-foreground flex items-center gap-1.5">
              <SlidersHorizontal className="h-4 w-4 text-muted-foreground" />
              Filter & Sort
            </h4>
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search by mission / UAV ID..."
                className="h-8.5 w-full rounded-md border border-border bg-surface pl-8 pr-3 text-[12px] outline-none focus:border-primary"
              />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <select
                value={filterUav}
                onChange={(e) => setFilterUav(e.target.value)}
                className="h-8 rounded-md border border-border bg-surface px-2 text-[11px] outline-none"
              >
                <option value="all">All UAVs</option>
                {uavIds.map((id) => (
                  <option key={id} value={id}>{id}</option>
                ))}
              </select>
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as any)}
                className="h-8 rounded-md border border-border bg-surface px-2 text-[11px] outline-none"
              >
                <option value="date">Newest First</option>
                <option value="size">Largest Size</option>
                <option value="duration">Longest Duration</option>
              </select>
            </div>
          </div>
        </div>

        {/* Recordings List */}
        <div className="rounded-lg border border-border bg-card shadow-xs overflow-hidden">
          <div className="border-b border-border bg-surface px-4 py-3">
            <h3 className="text-[13.5px] font-semibold text-foreground">Mission Archive Library</h3>
          </div>
          {filteredRecordings.length === 0 ? (
            <div className="flex flex-col items-center justify-center p-12 text-center text-muted-foreground">
              <Video className="h-10 w-10 stroke-1 mb-2.5" />
              <p className="text-[13px] font-medium">No recordings found matching search criteria.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-border text-[11px] text-muted-foreground uppercase bg-surface/50 font-medium">
                    <th className="px-4 py-2.5">Thumbnail</th>
                    <th className="px-4 py-2.5">Mission ID</th>
                    <th className="px-4 py-2.5">Source UAV</th>
                    <th className="px-4 py-2.5">Created Date</th>
                    <th className="px-4 py-2.5">Duration</th>
                    <th className="px-4 py-2.5">File Size</th>
                    <th className="px-4 py-2.5">Security</th>
                    <th className="px-4 py-2.5 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border text-[12.5px]">
                  {filteredRecordings.map((r) => (
                    <tr key={r.id} className="hover:bg-surface-2/45 transition-colors">
                      <td className="px-4 py-2.5">
                        <div className="h-10 w-14 rounded bg-black border border-border overflow-hidden flex items-center justify-center">
                          {r.thumbnail ? (
                            <img src={r.thumbnail} className="w-full h-full object-cover" alt="" />
                          ) : (
                            <Video className="h-4 w-4 text-muted-foreground" />
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-2.5 font-semibold text-foreground">{r.missionId}</td>
                      <td className="px-4 py-2.5 font-mono text-[11.5px]">{r.uavId}</td>
                      <td className="px-4 py-2.5 text-muted-foreground">{formatDateTime(r.startTime)}</td>
                      <td className="px-4 py-2.5 font-medium">{formatDuration(r.durationMs)}</td>
                      <td className="px-4 py-2.5 text-tabular">{formatBytes(r.fileSizeBytes)}</td>
                      <td className="px-4 py-2.5">
                        <span className="inline-flex items-center gap-1 text-[10.5px] bg-success-muted text-success px-2 py-0.5 rounded font-medium border border-success/10">
                          <Shield className="h-3 w-3" />
                          AES-GCM
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-right space-x-1.5">
                        <button
                          onClick={() => handlePlay(r.id)}
                          disabled={loadingPlayId !== null}
                          className="inline-flex items-center justify-center h-7 px-2.5 rounded bg-primary text-primary-foreground text-[11px] font-semibold hover:bg-primary/95 transition-colors cursor-pointer disabled:opacity-50"
                        >
                          {loadingPlayId === r.id ? (
                            <div className="h-3 w-3 animate-spin rounded-full border-2 border-primary-foreground border-t-transparent" />
                          ) : (
                            <>
                              <Eye className="h-3 w-3 mr-1" />
                              Playback
                            </>
                          )}
                        </button>
                        <a
                          href={`${GATEWAY_URL}/api/recordings/${r.id}/download`}
                          className="inline-flex items-center justify-center h-7 w-7 rounded border border-border bg-background text-muted-foreground hover:bg-surface-2 hover:text-foreground transition-colors cursor-pointer"
                          title="Download recording"
                        >
                          <Download className="h-3.5 w-3.5" />
                        </a>
                        <button
                          onClick={() => handleDelete(r.id)}
                          className="inline-flex items-center justify-center h-7 w-7 rounded border border-critical/20 bg-critical-muted text-critical hover:bg-critical hover:text-white transition-colors cursor-pointer"
                          title="Delete recording"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Synchronized Playback Modal Player */}
      {playingSession && (
        <PlaybackModal 
          session={playingSession} 
          onClose={() => setPlayingSession(null)} 
        />
      )}
    </AppShell>
  );
}

// ── PLAYBACK PLAYER MODAL WITH HUD TELEMETRY OVERLAY ─────────────────────────
function PlaybackModal({ session, onClose }: { session: RecordingSession; onClose: () => void }) {
  const [frameIdx, setFrameIdx] = useState(0);
  const [isPlaying, setIsPlaying] = useState(true);
  const [playbackSpeed, setPlaybackSpeed] = useState(1.0);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [syncHUD, setSyncHUD] = useState<RecordingMetadata | null>(null);
  
  const containerRef = useRef<HTMLDivElement>(null);
  const timerRef = useRef<any>(null);

  const totalFrames = session.frames.length;
  const currentFrame = session.frames[frameIdx];

  // Find nearest telemetry metadata row matching the current frame timestamp index
  useEffect(() => {
    if (!currentFrame || session.metadata.length === 0) return;
    
    // Nearest timestamp match
    let bestMatch = session.metadata[0];
    let minDiff = Math.abs(session.metadata[0].ts - currentFrame.ts);
    
    for (const meta of session.metadata) {
      const diff = Math.abs(meta.ts - currentFrame.ts);
      if (diff < minDiff) {
        minDiff = diff;
        bestMatch = meta;
      }
    }
    setSyncHUD(bestMatch);
  }, [frameIdx, currentFrame, session.metadata]);

  // Frame timer looping
  useEffect(() => {
    if (!isPlaying || totalFrames === 0) {
      if (timerRef.current) clearInterval(timerRef.current);
      return;
    }

    const intervalMs = Math.round(100 / playbackSpeed); // default ~10 FPS (100ms)
    
    timerRef.current = setInterval(() => {
      setFrameIdx((prev) => {
        if (prev >= totalFrames - 1) {
          setIsPlaying(false);
          return prev;
        }
        return prev + 1;
      });
    }, intervalMs);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isPlaying, playbackSpeed, totalFrames]);

  const togglePlay = () => setIsPlaying(!isPlaying);

  const handleSeek = (idx: number) => {
    setFrameIdx(idx);
    setIsPlaying(false);
  };

  const toggleFullscreen = () => {
    if (!containerRef.current) return;
    if (!document.fullscreenElement) {
      containerRef.current.requestFullscreen().then(() => setIsFullscreen(true));
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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-xs p-4">
      <div 
        ref={containerRef}
        className={`relative flex flex-col bg-card border border-border rounded-lg overflow-hidden shadow-2xl transition-all ${isFullscreen ? "w-screen h-screen rounded-none bg-black" : "w-full max-w-5xl h-[650px]"}`}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border bg-surface px-4 py-3 shrink-0">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-success animate-pulse" />
            <h3 className="text-[13.5px] font-bold text-foreground">
              Encrypted Swarm Playback · {session.missionId} ({session.uavId})
            </h3>
          </div>
          <button 
            onClick={onClose} 
            className="h-7 w-7 rounded hover:bg-surface-2 flex items-center justify-center text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Main Split Screen Area: Video Frame + Synced HUD Overlay */}
        <div className="flex-1 min-h-0 relative flex flex-col md:flex-row bg-neutral-950">
          {/* Main Video Frame */}
          <div className="flex-1 relative flex items-center justify-center bg-black overflow-hidden h-full">
            {currentFrame ? (
              <img 
                src={currentFrame.frame} 
                alt="Encrypted Frame" 
                className="w-full h-full object-contain"
              />
            ) : (
              <div className="text-muted-foreground flex flex-col items-center gap-2">
                <AlertCircle className="h-8 w-8 text-muted-foreground" />
                <span className="text-[12px]">No frame sequence loaded</span>
              </div>
            )}

            {/* In-Video Synced Alert Overlay */}
            {syncHUD && syncHUD.status !== "nominal" && (
              <div className="absolute top-4 left-4 z-10 bg-critical/90 backdrop-blur border border-critical/20 text-white text-[11px] font-semibold px-3 py-1.5 rounded shadow-md flex items-center gap-1.5 animate-pulse">
                <ShieldAlert className="h-4 w-4" />
                <span>UAV WARNING: {syncHUD.status.toUpperCase()}</span>
              </div>
            )}
          </div>

          {/* Right Hand / Overlay HUD Telemetry Dashboard Panel */}
          <div className={`w-full md:w-80 shrink-0 border-l border-border bg-card flex flex-col ${isFullscreen ? "opacity-90 max-h-[400px] absolute right-4 top-16 rounded border bg-card/90" : "h-full"}`}>
            <div className="border-b border-border bg-surface px-4 py-2.5 flex items-center gap-1.5">
              <Compass className="h-4 w-4 text-primary" />
              <h4 className="text-[12.5px] font-bold text-foreground">Synchronized Telemetry HUD</h4>
            </div>
            
            <div className="flex-1 overflow-y-auto p-4 space-y-3.5 text-[12px]">
              {syncHUD ? (
                <>
                  {/* GPS & Alt */}
                  <div className="grid grid-cols-2 gap-2">
                    <div className="bg-surface border border-border p-2.5 rounded">
                      <span className="text-[9px] uppercase tracking-wider text-muted-foreground block">Latitude</span>
                      <span className="font-mono font-semibold text-foreground text-[12px]">{syncHUD.lat.toFixed(5)}</span>
                    </div>
                    <div className="bg-surface border border-border p-2.5 rounded">
                      <span className="text-[9px] uppercase tracking-wider text-muted-foreground block">Longitude</span>
                      <span className="font-mono font-semibold text-foreground text-[12px]">{syncHUD.lon.toFixed(5)}</span>
                    </div>
                  </div>

                  {/* Altitude & Speed */}
                  <div className="grid grid-cols-2 gap-2">
                    <div className="bg-surface border border-border p-2.5 rounded flex items-center gap-2">
                      <Compass className="h-4 w-4 text-primary shrink-0" />
                      <div>
                        <span className="text-[9px] uppercase tracking-wider text-muted-foreground block">Altitude</span>
                        <span className="font-semibold text-foreground text-[12px]">{syncHUD.altitude} m</span>
                      </div>
                    </div>
                    <div className="bg-surface border border-border p-2.5 rounded flex items-center gap-2">
                      <Gauge className="h-4 w-4 text-primary shrink-0" />
                      <div>
                        <span className="text-[9px] uppercase tracking-wider text-muted-foreground block">Speed</span>
                        <span className="font-semibold text-foreground text-[12px]">{syncHUD.speed.toFixed(1)} m/s</span>
                      </div>
                    </div>
                  </div>

                  {/* Battery Voltage & Percentage */}
                  <div className="bg-surface border border-border p-3 rounded flex items-center justify-between">
                    <div className="flex items-center gap-2.5">
                      <Battery className="h-4.5 w-4.5 text-success" />
                      <div>
                        <span className="text-[9px] uppercase tracking-wider text-muted-foreground block">Battery Capacity</span>
                        <span className="font-semibold text-foreground text-[13px]">{syncHUD.battery}%</span>
                      </div>
                    </div>
                    <span className="text-[11px] font-mono text-muted-foreground font-medium">{syncHUD.voltage.toFixed(1)} V</span>
                  </div>

                  {/* Signal RSSI & Link Quality */}
                  <div className="bg-surface border border-border p-3 rounded flex items-center gap-3">
                    <Wifi className="h-4.5 w-4.5 text-primary shrink-0" />
                    <div className="flex-1">
                      <div className="flex justify-between items-center mb-1">
                        <span className="text-[9px] uppercase tracking-wider text-muted-foreground">Signal Quality (RSSI)</span>
                        <span className="font-semibold text-foreground text-[11px]">{syncHUD.rssi} dBm</span>
                      </div>
                      <div className="w-full h-1.5 bg-border rounded-full overflow-hidden">
                        <div 
                          className="h-full bg-primary" 
                          style={{ width: `${Math.max(0, Math.min(100, 100 + syncHUD.rssi))}%` }}
                        />
                      </div>
                    </div>
                  </div>

                  {/* Security Profile & Status */}
                  <div className="border border-border rounded-lg bg-surface/50 p-3 space-y-2">
                    <div className="flex justify-between items-center text-[11px]">
                      <span className="text-muted-foreground">Encryption Status:</span>
                      <span className="inline-flex items-center gap-1 font-semibold text-success">
                        <Shield className="h-3 w-3" />
                        AES-256-GCM
                      </span>
                    </div>
                    <div className="flex justify-between items-center text-[11px]">
                      <span className="text-muted-foreground">Swarm State:</span>
                      <span className={`font-semibold capitalize ${syncHUD.status === "nominal" ? "text-success" : "text-critical animate-pulse"}`}>
                        {syncHUD.status}
                      </span>
                    </div>
                  </div>
                </>
              ) : (
                <div className="h-full flex items-center justify-center text-muted-foreground text-center py-12">
                  <span>Awaiting synchronized telemetry stream...</span>
                </div>
              )}
            </div>
            
            <div className="border-t border-border bg-surface px-4 py-2.5 text-[10px] text-muted-foreground font-mono flex justify-between shrink-0">
              <span>Time Index: {currentFrame ? formatDuration(currentFrame.ts) : "0:00"}</span>
              <span>Frame: {frameIdx + 1} / {totalFrames}</span>
            </div>
          </div>
        </div>

        {/* Video Control Bar Panel */}
        <div className="bg-surface border-t border-border p-4 flex flex-col gap-3.5 shrink-0 w-full">
          {/* Progress Timeline Slider */}
          <div className="flex items-center gap-3">
            <span className="text-[11px] font-mono text-muted-foreground w-10 shrink-0">
              {currentFrame ? formatDuration(currentFrame.ts) : "0:00"}
            </span>
            <input 
              type="range"
              min="0"
              max={totalFrames - 1}
              value={frameIdx}
              onChange={(e) => handleSeek(parseInt(e.target.value))}
              className="flex-1 h-1.5 rounded-full bg-border appearance-none cursor-pointer outline-none accent-primary"
            />
            <span className="text-[11px] font-mono text-muted-foreground w-10 text-right shrink-0">
              {formatDuration(session.durationMs)}
            </span>
          </div>

          {/* Media Controls */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <button 
                onClick={togglePlay}
                className="flex items-center justify-center h-8.5 px-4 rounded bg-primary text-primary-foreground text-[12px] font-bold hover:bg-primary/95 transition-colors cursor-pointer"
              >
                {isPlaying ? "Pause" : "Play"}
              </button>

              <div className="flex items-center gap-2">
                <span className="text-[11px] text-muted-foreground uppercase tracking-wider">Speed</span>
                <select
                  value={playbackSpeed}
                  onChange={(e) => setPlaybackSpeed(parseFloat(e.target.value))}
                  className="h-7.5 rounded border border-border bg-background px-2 text-[11px] font-medium outline-none"
                >
                  <option value="0.5">0.5x</option>
                  <option value="1.0">1.0x</option>
                  <option value="1.5">1.5x</option>
                  <option value="2.0">2.0x</option>
                </select>
              </div>
            </div>

            <button
              onClick={toggleFullscreen}
              className="flex items-center justify-center h-8 w-8 rounded border border-border bg-background text-muted-foreground hover:bg-surface-2 hover:text-foreground transition-colors cursor-pointer"
              title="Fullscreen"
            >
              {isFullscreen ? <Minimize2 className="h-4.5 w-4.5" /> : <Maximize2 className="h-4.5 w-4.5" />}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function X({ className }: { className?: string }) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor" className={className}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" />
    </svg>
  );
}
