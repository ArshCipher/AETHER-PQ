import * as fs from "fs";
import * as path from "path";
import { IPasswordHasher, PBKDF2Hasher } from "./hasher";

export interface IAuthProvider {
  verifyCredentials(username: string, passwordPlain: string): Promise<boolean>;
  getRole(username: string): Promise<string | null>;
  getLockoutStatus(username: string): { locked: boolean; minutesRemaining: number };
}

export class JsonAuthProvider implements IAuthProvider {
  private configPath: string;
  private users: any = {};
  private hasher: IPasswordHasher;
  
  // Track consecutive failures: username -> { attempts, lockedUntil }
  private lockouts = new Map<string, { attempts: number; lockedUntil: number }>();
  private readonly MAX_ATTEMPTS = 5;
  private readonly LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

  constructor(
    relativeConfigPath: string = "../../config/users.json",
    hasher: IPasswordHasher = new PBKDF2Hasher()
  ) {
    this.configPath = path.resolve(process.cwd(), relativeConfigPath);
    this.hasher = hasher;
    this.loadAndMigrate();
  }

  private loadAndMigrate() {
    try {
      if (!fs.existsSync(this.configPath)) {
        console.warn(`[Auth] Config file not found at ${this.configPath}. Initializing empty user database.`);
        this.saveUsers();
        return;
      }

      const raw = fs.readFileSync(this.configPath, "utf-8");
      const data = JSON.parse(raw);
      this.users = data.users || {};

      let migrated = false;
      for (const username of Object.keys(this.users)) {
        const u = this.users[username];
        if (u.password_plain) {
          const salt = this.hasher.generateSalt();
          const hash = this.hasher.hash(u.password_plain, salt);
          u.salt = salt;
          u.hash = hash;
          delete u.password_plain;
          migrated = true;
        }
      }

      if (migrated) {
        data.updated_at = new Date().toISOString();
        this.saveUsers(data);
        console.log("[Auth] Migrated plain passwords in users.json to secure salted hashes.");
      }
    } catch (e) {
      console.error("[Auth] Failed to load users configuration:", e);
    }
  }

  private saveUsers(fullData?: any) {
    try {
      const data = fullData || {
        schema_version: "1.0.0",
        application_version: "1.0.0",
        protocol_version: "1.0.0",
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        users: this.users
      };
      fs.writeFileSync(this.configPath, JSON.stringify(data, null, 2), "utf-8");
    } catch (e) {
      console.error("[Auth] Failed to save users database:", e);
    }
  }

  public getLockoutStatus(username: string): { locked: boolean; minutesRemaining: number } {
    const lockout = this.lockouts.get(username);
    if (lockout && lockout.lockedUntil > Date.now()) {
      const diff = lockout.lockedUntil - Date.now();
      return { locked: true, minutesRemaining: Math.ceil(diff / 60000) };
    }
    return { locked: false, minutesRemaining: 0 };
  }

  public async verifyCredentials(username: string, passwordPlain: string): Promise<boolean> {
    this.loadAndMigrate(); // Reload to capture administrative user modifications

    // 1. Check Lockout status
    const status = this.getLockoutStatus(username);
    if (status.locked) {
      throw new Error(`Account is temporarily locked due to repeated failures. Try again in ${status.minutesRemaining} minutes.`);
    }

    const user = this.users[username];
    if (!user || !user.hash || !user.salt) {
      this.recordFailure(username);
      return false;
    }

    // 2. Hash match verification
    const computedHash = this.hasher.hash(passwordPlain, user.salt);
    const matches = computedHash === user.hash;

    if (matches) {
      // Clear failure record upon successful login
      this.lockouts.delete(username);
      return true;
    } else {
      this.recordFailure(username);
      return false;
    }
  }

  private recordFailure(username: string) {
    const lockout = this.lockouts.get(username);
    const attempts = (lockout ? lockout.attempts : 0) + 1;

    if (attempts >= this.MAX_ATTEMPTS) {
      const lockedUntil = Date.now() + this.LOCKOUT_DURATION_MS;
      this.lockouts.set(username, { attempts, lockedUntil });
      console.warn(`[Auth] User ${username} locked out due to ${attempts} failed attempts.`);
    } else {
      this.lockouts.set(username, { attempts, lockedUntil: 0 });
    }
  }

  public async getRole(username: string): Promise<string | null> {
    this.loadAndMigrate();
    const user = this.users[username];
    return user ? user.role : null;
  }
}
