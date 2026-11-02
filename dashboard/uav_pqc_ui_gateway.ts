import { spawn } from "child_process";
import type { ChildProcess } from "child_process";
import { WebSocketServer, WebSocket } from "ws";
import { createServer } from "http";
import * as fs from "fs";
import * as crypto from "crypto";
import { JsonAuthProvider } from "./auth_provider";
import { LogManager } from "./log_manager";
import { hasPermission, Permission } from "./rbac";

const auth = new JsonAuthProvider();
const logManager = new LogManager();

const AETHER_CA_BIN = process.env.AETHER_CA_BIN || "../../uav_pqc/build/tools/process_sim/uav_pqc_ca_node";
const AETHER_GCS_BIN = process.env.AETHER_GCS_BIN || "../../uav_pqc/build/tools/process_sim/uav_pqc_gcs_node";
const AETHER_UAV_BIN = process.env.AETHER_UAV_BIN || "../../uav_pqc/build/tools/process_sim/uav_pqc_uav_node";
const AETHER_HARDWARE_CONTROL_SH = process.env.AETHER_HARDWARE_CONTROL_SH || "../../uav_pqc/deployment/hardware_control.sh";
const AETHER_HARDWARE_BENCHMARK_BIN = process.env.AETHER_HARDWARE_BENCHMARK_BIN || "../../uav_pqc/build/tools/hardware_benchmark/uav_pqc_hardware_benchmark";
const AETHER_DOWNLOAD_DIR = process.env.AETHER_DOWNLOAD_DIR || "./downloads";
const AETHER_RECORDINGS_DIR = process.env.AETHER_RECORDINGS_DIR || "./data/recordings";
if (!fs.existsSync(AETHER_DOWNLOAD_DIR)) fs.mkdirSync(AETHER_DOWNLOAD_DIR, { recursive: true });
if (!fs.existsSync(AETHER_RECORDINGS_DIR)) fs.mkdirSync(AETHER_RECORDINGS_DIR, { recursive: true });

// AES-256-GCM Symmetric Key for Encrypted Recording Storage
const RECORDING_ENCRYPTION_KEY = crypto.createHash("sha256").update("AETHER_PQ_MISSION_REC_SECRET_KEY_2026").digest();

function encryptRecordingData(dataObj: any): Buffer {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", RECORDING_ENCRYPTION_KEY, iv);
  const jsonStr = JSON.stringify(dataObj);
  const encrypted = Buffer.concat([cipher.update(jsonStr, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Header: 4-byte magic "AETH", 12-byte IV, 16-byte Tag
  const header = Buffer.alloc(32);
  header.write("AETH", 0, 4, "ascii");
  iv.copy(header, 4);
  tag.copy(header, 16);
  return Buffer.concat([header, encrypted]);
}

function decryptRecordingData(buf: Buffer): any {
  if (buf.length < 32 || buf.toString("ascii", 0, 4) !== "AETH") {
    // Unencrypted or raw JSON fallback
    return JSON.parse(buf.toString("utf8"));
  }
  const iv = buf.subarray(4, 16);
  const tag = buf.subarray(16, 32);
  const ciphertext = buf.subarray(32);
  const decipher = crypto.createDecipheriv("aes-256-gcm", RECORDING_ENCRYPTION_KEY, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(decrypted.toString("utf8"));
}

// Recording Manager Interfaces & State
interface RecordingFrame {
  ts: number;
  uavId: string;
  frame: string; // Base64 JPEG data URL
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
  endTime?: number;
  durationMs: number;
  frames: RecordingFrame[];
  metadata: RecordingMetadata[];
  encrypted: boolean;
  autoStarted?: boolean;
}

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

const recordingConfig = {
  autoRecordOnMissionStart: true
};

let activeRecording: RecordingSession | null = null;

function getStorageBytes(): number {
  try {
    const files = fs.readdirSync(AETHER_RECORDINGS_DIR);
    let total = 0;
    for (const f of files) {
      if (f.endsWith(".aetherrec") || f.endsWith(".json")) {
        const stat = fs.statSync(`${AETHER_RECORDINGS_DIR}/${f}`);
        total += stat.size;
      }
    }
    return total;
  } catch {
    return 0;
  }
}

function broadcastRecordingStatus() {
  const summary = activeRecording ? {
    id: activeRecording.id,
    missionId: activeRecording.missionId,
    uavId: activeRecording.uavId,
    startTime: activeRecording.startTime,
    frameCount: activeRecording.frames.length,
    durationMs: Date.now() - activeRecording.startTime,
    autoStarted: !!activeRecording.autoStarted
  } : null;

  const msg = JSON.stringify({
    type: "recording_status",
    data: {
      isRecording: !!activeRecording,
      activeRecording: summary,
      autoRecordOnMissionStart: recordingConfig.autoRecordOnMissionStart,
      storageBytes: getStorageBytes()
    }
  });

  for (const c of clients) {
    if (c.readyState === WebSocket.OPEN) c.send(msg);
  }
}

function startRecording(missionId = "MSN-2026-ALPHA", uavId = "UAV-001", autoStarted = false): RecordingSession {
  if (activeRecording) {
    stopRecording();
  }

  const id = `REC-${Date.now()}`;
  const filename = `${Date.now()}_${missionId.replace(/[^a-zA-Z0-9_\-]/g, "")}_${uavId.replace(/[^a-zA-Z0-9_\-]/g, "")}.aetherrec`;
  
  activeRecording = {
    id,
    filename,
    missionId,
    uavId,
    startTime: Date.now(),
    durationMs: 0,
    frames: [],
    metadata: [],
    encrypted: true,
    autoStarted
  };

  addLog("mission", "info", "GCS", `Mission video recording STARTED · ${missionId} (${uavId})`);
  broadcastRecordingStatus();
  return activeRecording;
}

function stopRecording(): RecordingSummary | null {
  if (!activeRecording) return null;

  // Turn off auto-record to prevent immediate restart from incoming video frames
  recordingConfig.autoRecordOnMissionStart = false;

  const session = activeRecording;
  session.endTime = Date.now();
  session.durationMs = session.endTime - session.startTime;
  activeRecording = null;

  const filepath = `${AETHER_RECORDINGS_DIR}/${session.filename}`;
  try {
    const encBuffer = encryptRecordingData(session);
    fs.writeFileSync(filepath, encBuffer);
    console.log(`[Recording] Mission recording saved securely to ${filepath} (${Math.round(encBuffer.length / 1024)} KB)`);
    addLog("mission", "success", "GCS", `Mission recording SAVED · ${session.missionId} (${session.frames.length} frames, ${Math.round(encBuffer.length / 1024)} KB)`);
  } catch (err) {
    console.error("[Recording] Failed to save recording:", err);
  }

  broadcastRecordingStatus();

  return {
    id: session.id,
    filename: session.filename,
    missionId: session.missionId,
    uavId: session.uavId,
    startTime: session.startTime,
    durationMs: session.durationMs,
    frameCount: session.frames.length,
    fileSizeBytes: fs.existsSync(filepath) ? fs.statSync(filepath).size : 0,
    encrypted: true,
    thumbnail: session.frames[0]?.frame
  };
}

function listRecordings(): RecordingSummary[] {
  try {
    const files = fs.readdirSync(AETHER_RECORDINGS_DIR);
    const list: RecordingSummary[] = [];

    for (const f of files) {
      if (!f.endsWith(".aetherrec") && !f.endsWith(".json")) continue;
      const filepath = `${AETHER_RECORDINGS_DIR}/${f}`;
      try {
        const stat = fs.statSync(filepath);
        const fileBuf = fs.readFileSync(filepath);
        const data = decryptRecordingData(fileBuf);
        list.push({
          id: data.id || f.replace(/\.[^/.]+$/, ""),
          filename: f,
          missionId: data.missionId || "MSN-GENERAL",
          uavId: data.uavId || "UAV-001",
          startTime: data.startTime || stat.mtimeMs,
          durationMs: data.durationMs || 0,
          frameCount: data.frames?.length || 0,
          fileSizeBytes: stat.size,
          encrypted: data.encrypted ?? true,
          thumbnail: data.frames?.[0]?.frame
        });
      } catch (err) {
        console.error(`[Recording] Failed to parse recording file ${f}:`, err);
      }
    }

    return list.sort((a, b) => b.startTime - a.startTime);
  } catch {
    return [];
  }
}

// Ephemeral server-wide session signing secret (rotates on reboot)
const sessionSecret = crypto.randomBytes(32).toString("hex");
const activeSessions = new Set<string>();

function createSessionToken(username: string, role: string): string {
  const expires = Date.now() + 30 * 60 * 1000; // 30-minute session expiry
  const data = `${username}:${role}:${expires}`;
  const sig = crypto.createHmac("sha256", sessionSecret).update(data).digest("hex");
  return `${data}:${sig}`;
}

function verifySessionToken(token: string): { username: string; role: string } | null {
  try {
    const parts = token.split(":");
    if (parts.length !== 4) return null;
    const [username, role, expiresStr, sig] = parts;
    const expires = parseInt(expiresStr, 10);
    if (expires < Date.now()) return null; // Session expired

    const data = `${username}:${role}:${expiresStr}`;
    const expectedSig = crypto.createHmac("sha256", sessionSecret).update(data).digest("hex");
    if (sig !== expectedSig) return null; // Compromised signature

    return { username, role };
  } catch {
    return null;
  }
}

// Types matching mock-data.ts schema
type UavStatus = "nominal" | "degraded" | "critical" | "offline" | "maintenance";
type PolicyMode = "L1-CLASSICAL" | "L2-HYBRID" | "L3-HYBRID" | "L4-PQ-ONLY";
type CryptoProfile = "X25519+ML-KEM-768" | "X25519+ML-KEM-1024" | "P-384+ML-KEM-1024" | "ML-KEM-1024";
type OperatingMode = "SURVEY" | "PATROL" | "RELAY" | "STRIKE-SIM" | "RTB" | "STANDBY";

interface UAV {
  id: string;
  callsign: string;
  mission: string;
  status: UavStatus;
  battery: number;
  speed: number;
  altitude: number;
  heading: number;
  rssi: number;
  sinr: number;
  latency: number;
  packetLoss: number;
  bandwidth: number;
  cpu: number;
  memory: number;
  temperature: number;
  energy: number;
  operatingMode: OperatingMode;
  cryptoProfile: CryptoProfile;
  policyMode: PolicyMode;
  epoch: number;
  link: "LTE" | "ETH" | "MESH";
  lastFrameMs: number;
  hasCamera: boolean;
  coord: { lat: number; lon: number };
  fleetGroup: "ALPHA" | "BRAVO" | "CHARLIE";
}

interface ActivityEvent {
  ts: string;
  kind: "policy" | "handshake" | "rotation" | "cert" | "link" | "alert" | "handover" | "emergency" | "override" | "mission";
  severity: "info" | "success" | "warning" | "critical";
  actor: string;
  message: string;
}

interface Alert {
  id: string;
  severity: "warning" | "critical" | "info";
  title: string;
  detail: string;
  source: string;
  ts: string;
}

// Initial default state (authoritative backend sync)
const state = {
  fleet: [
    {
      id: "UAV-001", callsign: "Falcon-101", mission: "Perimeter Survey · Sector 14",
      status: "offline" as UavStatus, battery: 100, speed: 0, altitude: 0, heading: 0,
      rssi: -50, sinr: 25.0, latency: 0, packetLoss: 0, bandwidth: 50.0,
      cpu: 0, memory: 0, temperature: 28.0, energy: 500,
      operatingMode: "STANDBY" as OperatingMode, cryptoProfile: "X25519+ML-KEM-1024" as CryptoProfile,
      policyMode: "L2-HYBRID" as PolicyMode, epoch: 1, link: "LTE" as const, lastFrameMs: 0,
      hasCamera: true,  // Physical UAV-1 (Intel OptiPlex 7020) has /dev/video0 attached
      coord: { lat: 28.6139, lon: 77.2090 }, fleetGroup: "ALPHA" as const,
    },
    {
      id: "UAV-002", callsign: "Raven-102", mission: "Coastal Patrol · Route Kilo",
      status: "offline" as UavStatus, battery: 100, speed: 0, altitude: 0, heading: 0,
      rssi: -50, sinr: 25.0, latency: 0, packetLoss: 0, bandwidth: 50.0,
      cpu: 0, memory: 0, temperature: 28.0, energy: 500,
      operatingMode: "STANDBY" as OperatingMode, cryptoProfile: "X25519+ML-KEM-1024" as CryptoProfile,
      policyMode: "L2-HYBRID" as PolicyMode, epoch: 1, link: "LTE" as const, lastFrameMs: 0,
      hasCamera: false,
      coord: { lat: 28.5820, lon: 77.2410 }, fleetGroup: "ALPHA" as const,
    },
    {
      id: "UAV-003", callsign: "Kite-103", mission: "Comms Relay · Node Delta",
      status: "offline" as UavStatus, battery: 100, speed: 0, altitude: 0, heading: 0,
      rssi: -50, sinr: 25.0, latency: 0, packetLoss: 0, bandwidth: 50.0,
      cpu: 0, memory: 0, temperature: 28.0, energy: 500,
      operatingMode: "STANDBY" as OperatingMode, cryptoProfile: "X25519+ML-KEM-1024" as CryptoProfile,
      policyMode: "L2-HYBRID" as PolicyMode, epoch: 1, link: "ETH" as const, lastFrameMs: 0,
      hasCamera: false,
      coord: { lat: 28.6440, lon: 77.1820 }, fleetGroup: "BRAVO" as const,
    },
    {
      id: "UAV-004", callsign: "Eagle-104", mission: "Search & Rescue · Sector 9",
      status: "offline" as UavStatus, battery: 100, speed: 0, altitude: 0, heading: 0,
      rssi: -50, sinr: 25.0, latency: 0, packetLoss: 0, bandwidth: 50.0,
      cpu: 0, memory: 0, temperature: 28.0, energy: 500,
      operatingMode: "STANDBY" as OperatingMode, cryptoProfile: "X25519+ML-KEM-1024" as CryptoProfile,
      policyMode: "L2-HYBRID" as PolicyMode, epoch: 1, link: "LTE" as const, lastFrameMs: 0,
      hasCamera: false,
      coord: { lat: 28.6250, lon: 77.2250 }, fleetGroup: "BRAVO" as const,
    }
  ] as UAV[],
  recentActivity: [] as ActivityEvent[],
  alerts: [] as Alert[],
  treekem: {
    epoch: 1,
    welcomeFragments: 10,
    welcomeSize: 1204, // Bytes
    rekeyDurationMs: 48,
    commitDigest: "0x3f5c71bde..."
  }
};

// Spawned processes list for cleanup
const processes: ChildProcess[] = [];
const uavProcesses = new Map<string, ChildProcess>();

function getTimestamp() {
  return new Date().toISOString().split("T")[1].slice(0, 8) + "Z";
}

function addLog(kind: ActivityEvent["kind"], severity: ActivityEvent["severity"], actor: string, message: string) {
  const log: ActivityEvent = { ts: getTimestamp(), kind, severity, actor, message };
  state.recentActivity.unshift(log);
  if (state.recentActivity.length > 50) state.recentActivity.pop();
  
  // Log event in security log
  logManager.logSecurityEvent(actor, severity, `${kind} · ${message}`);

  if (severity === "critical" || severity === "warning") {
    const alert: Alert = {
      id: "A-" + Math.floor(Math.random() * 9000 + 1000),
      severity: severity as Alert["severity"],
      title: message.split(" · ")[0],
      detail: message,
      source: actor,
      ts: log.ts
    };
    state.alerts.unshift(alert);
    if (state.alerts.length > 10) state.alerts.pop();
  }
  broadcastState();
}

// Spawn all C++ nodes dynamically
function startSimulation() {
  console.log("[Gateway] Launching PQC Simulator binaries...");

  const caIp = process.env.CA_IP || "127.0.0.1";
  const caPort = process.env.CA_PORT || "28000";
  const gcsIp = process.env.GCS_IP || "127.0.0.1";
  const gcsPort = process.env.GCS_PORT || "28001";
  const uavRoutes = process.env.UAV_ROUTES || `1:${gcsIp}:28003,2:${gcsIp}:28004,3:${gcsIp}:28005`;

  // 1. Launch CA Node
  const caBindIp = process.env.CA_BIND_IP || caIp;
  const ca = spawn(AETHER_CA_BIN, ["--ip", caBindIp, "--port", caPort]);
  processes.push(ca);
  addLog("cert", "success", "CA", `Certificate Authority node launched on ${caIp}:${caPort}`);

  ca.stdout.on("data", (data) => console.log(`[CA Stdout] ${data.toString().trim()}`));
  ca.stderr.on("data", (data) => console.error(`[CA Stderr] ${data.toString().trim()}`));

  // 2. Launch GCS Node
  const gcs = spawn(AETHER_GCS_BIN, [
    "--ip", gcsIp, "--port", gcsPort,
    "--ca-ip", caIp, "--ca-port", caPort,
    "--uav-routes", uavRoutes
  ]);
  processes.push(gcs);
  addLog("mission", "info", "GCS", `Ground Control Station active on ${gcsIp}:${gcsPort}`);

  gcs.stdout.on("data", (data) => {
    const lines = data.toString().split("\n");
    for (const line of lines) {
      const cleanLine = line.trim();
      if (!cleanLine) continue;
      console.log(`[GCS] ${cleanLine}`);

      // Check for structured UI_EVENT
      if (cleanLine.startsWith("[UI_EVENT]")) {
        try {
          const eventJson = cleanLine.substring(10).trim();
          const parsed = JSON.parse(eventJson);
          handleUIEvent(parsed, gcs);
        } catch (e) {
          console.error("[Gateway] Failed to parse UI_EVENT:", e);
        }
      }
    }
  });

  gcs.stderr.on("data", (data) => console.error(`[GCS Stderr] ${data.toString().trim()}`));

  // 3. Launch 3 UAV Nodes (if enabled)
  if (process.env.SPAWN_LOCAL_UAVS !== "false") {
    for (let i = 1; i <= 3; ++i) {
      setTimeout(() => {
        spawnUavNode(i);
      }, i * 1500); // Stagger startup to complete CA registration comfortably
    }
  } else {
    console.log("[Gateway] Local mock UAV processes disabled (waiting for physical swarm connections).");
    addLog("mission", "info", "GCS", "Awaiting physical hardware swarm connection over the network...");
  }
}

let maxUavIndex = 3;

function spawnUavNode(i: number) {
  const caIp = process.env.CA_IP || "127.0.0.1";
  const caPort = process.env.CA_PORT || "28000";
  const gcsIp = process.env.GCS_IP || "127.0.0.1";
  const gcsPort = process.env.GCS_PORT || "28001";
  
  let uavIp = "127.0.0.1";
  if (process.env.UAV_IP_PREFIX) {
    uavIp = `${process.env.UAV_IP_PREFIX}${i}`;
  }
  
  let uavPort = 28002 + i;
  if (process.env.UAV_PORTS) {
    const ports = process.env.UAV_PORTS.split(",");
    if (ports[i - 1]) {
      uavPort = parseInt(ports[i - 1], 10);
    }
  }

  const uavRoutes = process.env.UAV_ROUTES || `${gcsIp}:28003,${gcsIp}:28004,${gcsIp}:28005`;
  const uav = spawn(AETHER_UAV_BIN, [
    "--id", i.toString(),
    "--ip", uavIp,
    "--port", uavPort.toString(),
    "--gcs-ip", gcsIp,
    "--gcs-port", gcsPort,
    "--ca-ip", caIp,
    "--ca-port", caPort,
    "--uav-routes", uavRoutes
  ]);
  processes.push(uav);
  uavProcesses.set(`UAV-00${i}`, uav);
  addLog("link", "info", `UAV-00${i}`, `Launched UAV Node process on ${uavIp}:${uavPort}`);

  uav.stdout.on("data", (data) => console.log(`[UAV-${i}] ${data.toString().trim()}`));
  uav.stderr.on("data", (data) => console.error(`[UAV-${i} Stderr] ${data.toString().trim()}`));
}

// Telemetry tracking map
const lastTelemetryTimes = new Map<string, number>();
const offlineStartTimes = new Map<string, number>();

// Handle incoming C++ UI Event structures
function handleUIEvent(event: any, gcsProcess: ChildProcess) {
  if (event.event === "handshake" || event.event === "telemetry") {
    offlineStartTimes.delete(event.id);
  }

  if (event.event === "handshake") {
    lastTelemetryTimes.set(event.id, Date.now());
    let uav = state.fleet.find((u) => u.id === event.id);
    if (!uav) {
      uav = {
        id: event.id,
        callsign: `AETHER-${event.id.split("-")[1] || "00" + state.fleet.length}`,
        mission: "Dynamic Swarm Patrol",
        status: "nominal",
        battery: 100,
        speed: 18.0,
        altitude: 250,
        heading: 90,
        rssi: -50,
        sinr: 20.0,
        latency: 12,
        packetLoss: 0.0,
        bandwidth: 72.4,
        cpu: 18,
        memory: 40,
        temperature: 38.5,
        energy: 500,
        operatingMode: "STANDBY",
        cryptoProfile: (event.profile || "X25519+ML-KEM-1024") as CryptoProfile,
        policyMode: (state.fleet[0]?.policyMode || "L2-HYBRID") as PolicyMode,
        epoch: state.treekem.epoch,
        link: "ETH",
        lastFrameMs: 150,
        hasCamera: false,  // unknown at registration time; set true when first video_frame arrives
        coord: { lat: 28.6139, lon: 77.2090 },
        fleetGroup: "ALPHA"
      };
      state.fleet.push(uav);
      addLog("link", "success", event.id, `Dynamic node registered in Swarm Roster`);
    } else {
      uav.status = "nominal";
      lastTelemetryTimes.set(event.id, Date.now());
      uav.cpu = Math.floor(Math.random() * 20 + 20);
      uav.memory = Math.floor(Math.random() * 15 + 40);
      uav.latency = Math.floor(Math.random() * 15 + 85);
      uav.bandwidth = 72.4;
      addLog("handshake", "success", event.id, `Secure ACPE & Hybrid handshake complete · ${event.profile}`);
    }
  } else if (event.event === "treekem_enroll") {
    addLog("rotation", "info", "TreeKEM", `Enrolling member leaf keys for ${event.id}`);
  } else if (event.event === "treekem_rekey") {
    state.treekem.epoch = event.epoch;
    state.treekem.rekeyDurationMs = Math.floor(Math.random() * 12 + 38);
    state.treekem.welcomeSize = 1000 + Math.floor(Math.random() * 250);
    
    // Update all nominal UAVs to this epoch
    for (const uav of state.fleet) {
      if (uav.status === "nominal") {
        uav.epoch = event.epoch;
      }
    }
    addLog("rotation", "success", "TreeKEM", `Swarm group epoch advanced to e-${event.epoch}`);
  } else if (event.event === "telemetry") {
    const uav = state.fleet.find((u) => u.id === event.id);
    if (uav) {
      lastTelemetryTimes.set(event.id, Date.now());
      uav.status = event.status === "Degraded" ? "degraded" : event.status === "Critical" ? "critical" : "nominal";
      uav.altitude = event.altitude;
      if (event.voltage) {
        // Map 20V-24V range to 0-100% battery
        uav.battery = Math.max(0, Math.min(100, Math.round(((event.voltage - 20.0) / 4.0) * 100)));
      }
      uav.lastFrameMs = 0;
      broadcastState();

      if (activeRecording && activeRecording.uavId === event.id) {
        activeRecording.metadata.push({
          ts: Date.now() - activeRecording.startTime,
          uavId: event.id,
          lat: uav.coord.lat,
          lon: uav.coord.lon,
          altitude: uav.altitude,
          battery: uav.battery,
          voltage: event.voltage || 24.0,
          speed: uav.speed,
          rssi: uav.rssi,
          status: uav.status
        });
      }
    }
  } else if (event.event === "policy") {
    for (const uav of state.fleet) {
      uav.policyMode = event.mode as PolicyMode;
    }
    addLog("policy", "warning", "ACPE", `Swarmlink security policy elevated to ${event.mode}`);
  } else if (event.event === "query_result") {
    // Intercept file listing results (type 5) and emit as separate file_list event
    if (typeof event.result === "string" && event.result.startsWith("FILE_LIST:")) {
      const listPayload = event.result.substring(10); // strip "FILE_LIST:"
      const files = listPayload === "EMPTY_DIR" ? [] : listPayload.split("|").map((entry: string) => {
        const fields: Record<string, string> = {};
        entry.split(",").forEach((kv: string) => {
          const eq = kv.indexOf("=");
          if (eq !== -1) fields[kv.substring(0, eq)] = kv.substring(eq + 1);
        });
        return fields;
      });
      const msg = JSON.stringify({ type: "file_list", data: { id: event.id, files, ts: Date.now() } });
      for (const c of clients) {
        if (c.readyState === WebSocket.OPEN) c.send(msg);
      }
    } else {
      const msg = JSON.stringify({ type: "query_result", data: event });
      for (const c of clients) {
        if (c.readyState === WebSocket.OPEN) {
          c.send(msg);
        }
      }
    }
  } else if (event.event === "file_transfer_progress") {
    const msg = JSON.stringify({ type: "file_transfer_progress", data: event });
    for (const c of clients) {
      if (c.readyState === WebSocket.OPEN) c.send(msg);
    }
  } else if (event.event === "file_transfer_complete") {
    addLog("mission", "success", "GCS", `Secure file transfer complete · ${event.filename} (${Math.round(event.bytes / 1024)} KB)`);
    const msg = JSON.stringify({ type: "file_transfer_complete", data: event });
    for (const c of clients) {
      if (c.readyState === WebSocket.OPEN) c.send(msg);
    }
  } else if (event.event === "video_frame") {
    lastTelemetryTimes.set(event.id, Date.now());
    // Mark this UAV as camera-equipped when the first frame arrives
    const camUav = state.fleet.find((u) => u.id === event.id);
    if (camUav) {
      if (!camUav.hasCamera) {
        camUav.hasCamera = true;
      }
      if (camUav.status === "offline") {
        camUav.status = "nominal";
      }
    }

    // Auto-start recording if configured and no recording is currently running
    if (!activeRecording && recordingConfig.autoRecordOnMissionStart) {
      startRecording("MSN-AUTO-" + event.id, event.id, true);
    }

    if (activeRecording && (activeRecording.uavId === event.id || activeRecording.uavId === "ALL")) {
      activeRecording.frames.push({
        ts: Date.now() - activeRecording.startTime,
        uavId: event.id,
        frame: event.frame
      });
    }

    const msg = JSON.stringify({ type: "video_frame", data: event });
    for (const c of clients) {
      if (c.readyState === WebSocket.OPEN) c.send(msg);
    }
  }
}

// Websocket connection management
const clients = new Set<WebSocket>();

function broadcastState() {
  const json = JSON.stringify({ type: "state", data: state });
  for (const client of clients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(json);
    }
  }
}

const server = createServer((req, res) => {
  // Global CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "*");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  // Serve received files for download
  const urlObj = new URL(req.url || "", `http://${req.headers.host || "localhost"}`);
  const pathname = urlObj.pathname;

  // Recordings REST API Endpoints
  if (pathname === "/api/recordings" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ recordings: listRecordings(), storageBytes: getStorageBytes(), activeRecording }));
    return;
  }

  const recDetailMatch = pathname.match(/^\/api\/recordings\/([a-zA-Z0-9_\-]+)$/);
  if (recDetailMatch) {
    const recId = recDetailMatch[1];
    if (req.method === "GET") {
      const recordings = listRecordings();
      const summary = recordings.find((r) => r.id === recId || r.filename.startsWith(recId));
      if (!summary) {
        res.writeHead(404, { "Content-Type": "text/plain" });
        res.end("Recording Not Found");
        return;
      }
      try {
        const filepath = `${AETHER_RECORDINGS_DIR}/${summary.filename}`;
        const fileBuf = fs.readFileSync(filepath);
        const data = decryptRecordingData(fileBuf);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(data));
      } catch (err) {
        res.writeHead(500, { "Content-Type": "text/plain" });
        res.end("Failed to read recording");
      }
      return;
    } else if (req.method === "DELETE") {
      const recordings = listRecordings();
      const summary = recordings.find((r) => r.id === recId || r.filename.startsWith(recId));
      if (summary) {
        try {
          fs.unlinkSync(`${AETHER_RECORDINGS_DIR}/${summary.filename}`);
          addLog("mission", "info", "GCS", `Mission recording deleted · ${summary.filename}`);
          broadcastRecordingStatus();
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: true, storageBytes: getStorageBytes() }));
        } catch {
          res.writeHead(500, { "Content-Type": "text/plain" });
          res.end("Failed to delete recording");
        }
      } else {
        res.writeHead(404, { "Content-Type": "text/plain" });
        res.end("Recording Not Found");
      }
      return;
    }
  }

  const recDownloadMatch = pathname.match(/^\/api\/recordings\/([a-zA-Z0-9_\-]+)\/download$/);
  if (recDownloadMatch && req.method === "GET") {
    const recId = recDownloadMatch[1];
    const recordings = listRecordings();
    const summary = recordings.find((r) => r.id === recId || r.filename.startsWith(recId));
    if (!summary) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Recording Not Found");
      return;
    }
    const filepath = `${AETHER_RECORDINGS_DIR}/${summary.filename}`;
    if (fs.existsSync(filepath)) {
      const stat = fs.statSync(filepath);
      res.writeHead(200, {
        "Content-Type": "application/octet-stream",
        "Content-Disposition": `attachment; filename="${summary.filename}"`,
        "Content-Length": stat.size.toString(),
      });
      fs.createReadStream(filepath).pipe(res);
    } else {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("File missing");
    }
    return;
  }

  const downloadMatch = pathname.match(/^\/download\/(.+)$/);
  if (downloadMatch) {
    const filename = downloadMatch[1].replace(/\.\./g, ""); // strip path traversal
    const token = urlObj.searchParams.get("token") || "";
    const active = activeSessions.has(token);
    const decoded = verifySessionToken(token);
    
    if (!active || !decoded) {
      console.log(`[Gateway] Unauthorized download attempt from ${req.socket.remoteAddress}`);
      res.writeHead(401, { "Content-Type": "text/plain" });
      res.end("Unauthorized. Session token is missing, invalid, or expired.");
      return;
    }
    
    if (!hasPermission(decoded.role, "RetrieveUAVFiles")) {
      console.log(`[Gateway] Forbidden download attempt for role ${decoded.role}`);
      res.writeHead(403, { "Content-Type": "text/plain" });
      res.end("Forbidden. Lacks RetrieveUAVFiles permission.");
      return;
    }
    
    const isSafeFilename = /^[a-zA-Z0-9_\-\.]+$/.test(filename);
    if (!isSafeFilename) {
      console.log(`[Gateway] Rejected download attempt for unsafe filename: ${filename}`);
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("Bad Request. Path traversal or invalid download filename.");
      return;
    }
    
    const filepath = `${AETHER_DOWNLOAD_DIR}/${filename}`;
    const downloadName = (urlObj.searchParams.get("name") || filename).replace(/[\r\n]/g, "");
    console.log(`[Gateway] Download request by ${decoded.username}: filename=${filename} -> downloadName="${downloadName}"`);
    
    if (fs.existsSync(filepath)) {
      const stat = fs.statSync(filepath);
      res.writeHead(200, {
        "Content-Type": "application/octet-stream",
        "Content-Disposition": `attachment; filename="${downloadName}"`,
        "Content-Length": stat.size.toString(),
      });
      fs.createReadStream(filepath).pipe(res);
    } else {
      console.log(`[Gateway] Download error: file ${filepath} does not exist`);
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("File not found");
    }
    return;
  }
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("AETHER-PQ UI Gateway Running");
});

const wss = new WebSocketServer({ server });

wss.on("connection", (ws: WebSocket) => {
  clients.add(ws);
  ws.send(JSON.stringify({ type: "state", data: state }));
  console.log(`[Gateway] Frontend client connected. Total clients: ${clients.size}`);

  ws.on("message", async (message) => {
    try {
      const payload = JSON.parse(message.toString());
      console.log("[Gateway] Received client message:", payload);
      
      // Handle authentication with Lockout error handling
      if (payload.type === "auth") {
        try {
          const success = await auth.verifyCredentials(payload.username, payload.password);
          if (success) {
            const role = await auth.getRole(payload.username) || "Viewer";
            const token = createSessionToken(payload.username, role);
            activeSessions.add(token);
            
            (ws as any).user = payload.username;
            (ws as any).role = role;
            (ws as any).token = token;
            
            ws.send(JSON.stringify({ type: "auth_result", success: true, token, username: payload.username, role }));
            logManager.logSecurityEvent("Gateway", "info", `User ${payload.username} authenticated successfully as ${role}`, "Authentication");
            broadcastRecordingStatus();
          } else {
            ws.send(JSON.stringify({ type: "auth_result", success: false, error: "Invalid username or password" }));
            logManager.logSecurityEvent("Gateway", "warning", `Failed login attempt for user: ${payload.username}`, "Authentication");
          }
        } catch (e: any) {
          ws.send(JSON.stringify({ type: "auth_result", success: false, error: e.message }));
          logManager.logSecurityEvent("Gateway", "warning", `Lockout rejection on login attempt for ${payload.username}: ${e.message}`, "Authentication");
        }
        return;
      }

      // Handle session token authentication
      if (payload.type === "session_auth") {
        const token = payload.token;
        if (token && activeSessions.has(token)) {
          const decoded = verifySessionToken(token);
          if (decoded) {
            (ws as any).user = decoded.username;
            (ws as any).role = decoded.role;
            (ws as any).token = token;
            ws.send(JSON.stringify({ type: "session_auth_result", success: true, username: decoded.username, role: decoded.role }));
            logManager.logSecurityEvent(decoded.username, "info", "Reconnected WebSocket using active session token", "Authentication");
            broadcastRecordingStatus();
            return;
          }
        }
        ws.send(JSON.stringify({ type: "session_auth_result", success: false, error: "Invalid or expired session token" }));
        return;
      }

      // Handle session invalidation / logout
      if (payload.type === "logout") {
        const token = payload.token || (ws as any).token;
        if (token) {
          activeSessions.delete(token);
        }
        (ws as any).user = null;
        (ws as any).role = null;
        (ws as any).token = null;
        ws.send(JSON.stringify({ type: "logout_result", success: true }));
        logManager.logSecurityEvent("Gateway", "info", "Session logged out and token invalidated", "Authentication");
        return;
      }

      // Handle trigger commands
      if (payload.type === "command") {
        const user = (ws as any).user;
        const role = (ws as any).role;

        // Force authentication in gateway commands
        if (!user || !role) {
          ws.send(JSON.stringify({ type: "command_result", success: false, error: "Unauthenticated. Please log in first." }));
          logManager.logSecurityEvent("Gateway", "warning", `Unauthorized command trigger '${payload.command}' from unauthenticated connection`, "AccessControl");
          return;
        }

        // Map commands to specific permission items
        let permission: Permission | null = null;
        if (payload.command === "rekey") permission = "ManualPolicyControl";
        else if (payload.command === "policy" || payload.command === "broadcast_cmd") permission = "ManualPolicyControl";
        else if (payload.command === "query_uav") {
          if (payload.queryType === 5) permission = "ListUAVFiles";
          else permission = "QueryUAV";
        }
        else if (payload.command === "revoke") permission = "RevokeCertificates";
        else if (payload.command === "node-shutdown") permission = "OperatorOverride";
        else if (payload.command === "net-simulation") permission = "ManageSimulation";
        else if (payload.command === "run-benchmark") permission = "RunBenchmarks";
        else if (payload.command === "register-uav") permission = "IssueCertificates";
        else if (payload.command === "send_file") permission = "RetrieveUAVFiles";
        else if (payload.command === "d2d_handshake" || payload.command === "send_d2d_data") permission = "ManualPolicyControl";
        else if (payload.command === "start-recording" || payload.command === "stop-recording" || payload.command === "recording-config") permission = "ManualPolicyControl";

        const authorized = permission ? hasPermission(role, permission) : false;

        if (!authorized) {
          ws.send(JSON.stringify({ type: "command_result", success: false, error: `Unauthorized. Role ${role} lacks permission '${permission}' to execute '${payload.command}'.` }));
          logManager.logSecurityEvent("Gateway", "warning", `Unauthorized command trigger '${payload.command}' rejected for user ${user} (${role})`, "AccessControl");
          return;
        }

        // Log operator command to file audit log
        logManager.logOperatorCommand(user, role, payload.command, JSON.stringify(payload));

        const gcs = processes[1]; // GCS is the second process spawned
        
        if (payload.command === "rekey") {
          if (gcs && gcs.stdin && !gcs.stdin.destroyed) gcs.stdin.write("rekey\n");
        } else if (payload.command === "policy") {
          if (gcs && gcs.stdin && !gcs.stdin.destroyed) gcs.stdin.write(`policy:${payload.mode}\n`);
        } else if (payload.command === "broadcast_cmd") {
          if (gcs && gcs.stdin && !gcs.stdin.destroyed) gcs.stdin.write(`broadcast_cmd:${payload.cmdId}\n`);
        } else if (payload.command === "query_uav") {
          const match = payload.id.match(/\d+/);
          if (match && gcs && gcs.stdin && !gcs.stdin.destroyed) {
            const idx = parseInt(match[0], 10);
            const sanitizedPath = (payload.pathOrKey || "").replace(/[\r\n]/g, "");
            gcs.stdin.write(`query_uav:${idx}:${payload.queryType}:${sanitizedPath}\n`);
          }
        } else if (payload.command === "revoke") {
          // Parse UAV index from ID (e.g. UAV-002 -> index 2)
          const match = payload.id.match(/\d+/);
          if (match && gcs && gcs.stdin && !gcs.stdin.destroyed) {
            const idx = parseInt(match[0], 10);
            const written = gcs.stdin.write(`revoke:${idx}\n`);
            console.log(`[Gateway Debug] Written revoke to GCS stdin: ${written} (fd: ${idx})`);
          }
        } else if (payload.command === "d2d_handshake") {
          const initiatorProc = uavProcesses.get(payload.initiatorId);
          const match = payload.targetId.match(/\d+/);
          if (initiatorProc && initiatorProc.stdin && !initiatorProc.stdin.destroyed && match) {
            const targetIdx = parseInt(match[0], 10);
            initiatorProc.stdin.write(`d2d_handshake:${targetIdx}\n`);
            console.log(`[Gateway] Triggered D2D handshake from ${payload.initiatorId} to UAV-${targetIdx}`);
          }
        } else if (payload.command === "send_d2d_data") {
          const initiatorProc = uavProcesses.get(payload.initiatorId);
          const match = payload.targetId.match(/\d+/);
          if (initiatorProc && initiatorProc.stdin && !initiatorProc.stdin.destroyed && match) {
            const targetIdx = parseInt(match[0], 10);
            initiatorProc.stdin.write(`send_d2d_data:${targetIdx}:${payload.message}\n`);
            console.log(`[Gateway] Sent direct D2D message from ${payload.initiatorId} to UAV-${targetIdx}: ${payload.message}`);
          }
        } else if (payload.command === "node-shutdown") {
          const uavProc = uavProcesses.get(payload.id);
          if (uavProc) {
            uavProc.kill("SIGKILL");
            uavProcesses.delete(payload.id);
            const uav = state.fleet.find((u) => u.id === payload.id);
            if (uav) {
              uav.status = "offline";
              addLog("emergency", "critical", payload.id, `UAV process shutdown requested · link offline`);
            }
          }
        } else if (payload.command === "net-simulation") {
          let args: string[] = [];
          if (payload.mode === "delay") {
            args = ["net-delay", payload.mode.toString()];
            addLog("link", "warning", "Network", `Simulating ethernet delay: ${payload.delay}ms`);
          } else if (payload.mode === "loss") {
            args = ["net-loss", payload.loss.toString()];
            addLog("link", "critical", "Network", `Simulating ethernet packet loss: ${payload.loss}%`);
          } else if (payload.mode === "clear") {
            args = ["net-clear"];
            addLog("link", "success", "Network", "Simulated ethernet degradation cleared");
          }
          
          const script = spawn(AETHER_HARDWARE_CONTROL_SH, args);
          script.stdout.on("data", (d) => console.log(`[Netem] ${d.toString().trim()}`));
          script.stderr.on("data", (d) => console.error(`[Netem Err] ${d.toString().trim()}`));
        } else if (payload.command === "run-benchmark") {
          addLog("policy", "info", "Benchmark", "Starting native post-quantum cryptographic benchmark...");
          const bench = spawn(AETHER_HARDWARE_BENCHMARK_BIN, ["--output", "./hardware_benchmark_report"]);
          
          bench.on("exit", async () => {
            try {
              const reportContent = fs.readFileSync("./hardware_benchmark_report.json", "utf-8");
              const report = JSON.parse(reportContent);
              addLog("policy", "success", "Benchmark", "Hardware benchmark completed successfully");
              
              // Broadcast benchmark results
              const msg = JSON.stringify({ type: "benchmark_result", data: report });
              for (const c of clients) {
                if (c.readyState === WebSocket.OPEN) {
                  c.send(msg);
                }
              }
            } catch (err) {
              console.error("[Gateway] Failed to read benchmark report:", err);
            }
          });
        } else if (payload.command === "register-uav") {
          maxUavIndex++;
          addLog("link", "info", "GCS", `Operator requested dynamic registration for UAV-00${maxUavIndex}`);
          spawnUavNode(maxUavIndex);
        } else if (payload.command === "send_file") {
          const match = (payload.id as string)?.match(/\d+/);
          if (match) {
            const idx = parseInt(match[0], 10);
            if (gcs && gcs.stdin && !gcs.stdin.destroyed) {
              const sanitizedPath = (payload.filepath || "").replace(/[\r\n]/g, "");
              gcs.stdin.write(`query_uav:${idx}:6:${sanitizedPath}\n`);
              addLog("mission", "info", payload.id, `Secure file pull initiated · ${sanitizedPath}`);
              ws.send(JSON.stringify({ type: "command_result", success: true, message: `File transfer initiated from ${payload.id}` }));
            } else {
              ws.send(JSON.stringify({ type: "command_result", success: false, error: "GCS process not active or stdin closed" }));
            }
          } else {
            ws.send(JSON.stringify({ type: "command_result", success: false, error: "Invalid UAV ID" }));
          }
        } else if (payload.command === "start-recording") {
          const rec = startRecording(payload.missionId || "MSN-2026-ALPHA", payload.uavId || "UAV-001", false);
          ws.send(JSON.stringify({ type: "command_result", success: true, recording: rec }));
        } else if (payload.command === "stop-recording") {
          const summary = stopRecording();
          ws.send(JSON.stringify({ type: "command_result", success: true, recording: summary }));
        } else if (payload.command === "recording-config") {
          if (typeof payload.autoRecordOnMissionStart === "boolean") {
            recordingConfig.autoRecordOnMissionStart = payload.autoRecordOnMissionStart;
            addLog("mission", "info", "GCS", `Auto-record configuration set to ${payload.autoRecordOnMissionStart}`);
            broadcastRecordingStatus();
            ws.send(JSON.stringify({ type: "command_result", success: true, autoRecordOnMissionStart: recordingConfig.autoRecordOnMissionStart }));
          }
        }
      }
    } catch (e) {
      console.error("[Gateway] Message error:", e);
    }
  });

  ws.on("close", () => {
    clients.delete(ws);
    console.log(`[Gateway] Client disconnected. Total clients: ${clients.size}`);
  });
});

server.listen(3001, () => {
  console.log(`====================================================`);
  console.log(`AETHER-PQ UI Gateway running on ws://localhost:3001`);
  console.log(`====================================================`);
});

// Handle process termination cleanly
function shutdown() {
  console.log("\n[Gateway] Shutting down simulation processes...");
  for (const p of processes) {
    try {
      p.kill("SIGKILL");
    } catch {}
  }
  process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

// Active connection monitor
setInterval(() => {
  let changed = false;
  const now = Date.now();
  for (const uav of state.fleet) {
    if (uav.status !== "offline") {
      const lastTime = lastTelemetryTimes.get(uav.id) || 0;
      if (now - lastTime > 12000) { // 12 seconds timeout
        uav.status = "offline";
        offlineStartTimes.set(uav.id, now);
        addLog("link", "critical", uav.id, `Telemetry connection timed out (Node Offline)`);
        changed = true;
      }
    } else {
      const offlineStart = offlineStartTimes.get(uav.id);
      if (offlineStart && now - offlineStart > 30000) { // 30 seconds threshold
        offlineStartTimes.delete(uav.id);
        
        // Trigger programmatic GCS member revocation
        const match = uav.id.match(/\d+/);
        const gcs = processes[1];
        if (match && gcs && gcs.stdin && !gcs.stdin.destroyed) {
          const idx = parseInt(match[0], 10);
          gcs.stdin.write(`revoke:${idx}\n`);
          console.log(`[Auto-Revocation] UAV ${uav.id} has been offline for 30s. Triggered TreeKEM member revocation.`);
          addLog("link", "critical", uav.id, `UAV offline limit exceeded (30s) · Triggered auto-revocation & epoch rekey`);
        }
      }
    }
  }
  if (changed) {
    broadcastState();
  }
}, 1000);

// Start GCS/UAVs
startSimulation();
