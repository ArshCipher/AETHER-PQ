import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";

export class LogManager {
  private logDir: string;
  private operatorLogPath: string;
  private securityLogPath: string;

  private operatorBuffer: string[] = [];
  private securityBuffer: string[] = [];
  private lastSecurityHash: string = "";

  constructor(relativeLogDir: string = "../../logs") {
    this.logDir = path.resolve(process.cwd(), relativeLogDir);
    this.operatorLogPath = path.join(this.logDir, "aether_operator.log");
    this.securityLogPath = path.join(this.logDir, "aether_security.log");

    this.initDirAndChain();
    
    // Periodically flush logs to disk every 2 seconds to minimize write amplification/flash wear
    setInterval(() => this.flushLogs(), 2000);
  }

  private initDirAndChain() {
    try {
      if (!fs.existsSync(this.logDir)) {
        fs.mkdirSync(this.logDir, { recursive: true });
      }

      // Initialize the hash chain by parsing the last line of the security log
      if (fs.existsSync(this.securityLogPath)) {
        const content = fs.readFileSync(this.securityLogPath, "utf-8").trim();
        const lines = content.split("\n").filter(line => line.trim().length > 0);
        if (lines.length > 0) {
          const lastLine = lines[lines.length - 1];
          const match = lastLine.match(/curr_hash=([a-f0-9]{64})/);
          if (match) {
            this.lastSecurityHash = match[1];
            return;
          }
        }
      }
      this.lastSecurityHash = "0000000000000000000000000000000000000000000000000000000000000000";
    } catch (e) {
      console.error("[Log] Failed to initialize log manager:", e);
      this.lastSecurityHash = "0000000000000000000000000000000000000000000000000000000000000000";
    }
  }

  public logOperatorCommand(username: string, role: string, command: string, details: string) {
    const ts = new Date().toISOString();
    const line = `${ts} [OPERATOR] user=${username} role=${role} cmd="${command}" details="${details}"`;
    this.operatorBuffer.push(line);
  }

  public logSecurityEvent(
    actor: string,
    severity: string,
    message: string,
    eventType: string = "System",
    subsystem: string = "Gateway"
  ) {
    const ts = new Date().toISOString();
    const index = Date.now();
    
    // Construct data payload to hash
    const entryData = `${index}|${ts}|${this.lastSecurityHash}|${eventType}|${severity}|${actor}|${subsystem}|${message}`;
    
    // Hash chain linkage: Hash(n) = SHA256(index|ts|prev_hash|type|severity|actor|subsystem|msg)
    const currentHash = crypto.createHash("sha256")
      .update(entryData)
      .digest("hex");

    const prevHash = this.lastSecurityHash;
    this.lastSecurityHash = currentHash;

    const line = `${ts} [SECURITY] index=${index} prev_hash=${prevHash} curr_hash=${currentHash} type=${eventType} severity=${severity} actor=${actor} subsystem=${subsystem} msg="${message}"`;
    this.securityBuffer.push(line);
  }

  private flushLogs() {
    this.flushLogger(this.operatorLogPath, this.operatorBuffer);
    this.flushLogger(this.securityLogPath, this.securityBuffer);
  }

  private flushLogger(filePath: string, buffer: string[]) {
    if (buffer.length === 0) return;

    try {
      this.rotateIfNecessary(filePath);
      
      const content = buffer.join("\n") + "\n";
      fs.appendFileSync(filePath, content, "utf-8");
      buffer.length = 0; // Clear buffer
    } catch (e) {
      console.error(`[Log] Failed to flush logs to ${filePath}:`, e);
    }
  }

  private rotateIfNecessary(filePath: string) {
    try {
      if (!fs.existsSync(filePath)) return;

      const stats = fs.statSync(filePath);
      // Limit to 5 MB
      if (stats.size > 5 * 1024 * 1024) {
        console.log(`[Log] Log file ${filePath} exceeded 5 MB. Rotating...`);
        for (let i = 4; i >= 1; --i) {
          const oldName = `${filePath}.${i}`;
          const newName = `${filePath}.${i + 1}`;
          if (fs.existsSync(oldName)) {
            fs.renameSync(oldName, newName);
          }
        }
        fs.renameSync(filePath, `${filePath}.1`);
      }
    } catch (e) {
      console.error(`[Log] Error rotating file ${filePath}:`, e);
    }
  }
}
