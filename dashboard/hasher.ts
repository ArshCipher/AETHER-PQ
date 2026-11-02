import * as crypto from "crypto";

// Abstraction for Password Hashing
export interface IPasswordHasher {
  hash(password: string, salt: string): string;
  generateSalt(): string;
}

// Concrete PBKDF2 implementation
export class PBKDF2Hasher implements IPasswordHasher {
  private iterations = 10000;
  private keyLen = 32;
  private digest = "sha256";

  public hash(password: string, salt: string): string {
    return crypto.pbkdf2Sync(password, salt, this.iterations, this.keyLen, this.digest).toString("hex");
  }

  public generateSalt(): string {
    return crypto.randomBytes(16).toString("hex");
  }
}

// Stub implementation for Argon2 to allow simple future swap
export class Argon2Hasher implements IPasswordHasher {
  private fallback: PBKDF2Hasher;

  constructor() {
    this.fallback = new PBKDF2Hasher();
  }

  public hash(password: string, salt: string): string {
    try {
      // Future upgrade path:
      // const argon2 = require("argon2");
      // return argon2.hashSync(password, { salt: Buffer.from(salt, "hex") });
      return this.fallback.hash(password, salt);
    } catch {
      return this.fallback.hash(password, salt);
    }
  }

  public generateSalt(): string {
    return this.fallback.generateSalt();
  }
}
