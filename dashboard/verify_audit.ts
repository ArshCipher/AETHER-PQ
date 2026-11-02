import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";

function verifyAuditChain(relativeLogPath: string = "../../logs/aether_security.log") {
  const logPath = path.resolve(process.cwd(), relativeLogPath);
  console.log(`[Verification] Reading log file from: ${logPath}`);

  if (!fs.existsSync(logPath)) {
    console.error("[Verification] Error: Log file does not exist.");
    process.exit(1);
  }

  const content = fs.readFileSync(logPath, "utf-8").trim();
  const lines = content.split("\n").filter(line => line.trim().length > 0);

  console.log(`[Verification] Found ${lines.length} log entries to verify.`);

  let lastHash = "0000000000000000000000000000000000000000000000000000000000000000";
  let chainValid = true;

  // Regex matches index, prev_hash, curr_hash, type, severity, actor, subsystem, and msg
  const regex = /^(\S+) \[SECURITY\] index=(\d+) prev_hash=(\S+) curr_hash=(\S+) type=(\S+) severity=(\S+) actor=(\S+) subsystem=(\S+) msg="([\s\S]*?)"$/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const match = line.match(regex);

    if (!match) {
      console.error(`[Verification] Failure: Line ${i + 1} does not match structured log format!`);
      console.error(`[Line Content]: "${line}"`);
      chainValid = false;
      break;
    }

    const [_, ts, index, prevHash, currHash, eventType, severity, actor, subsystem, message] = match;

    // Check previous hash linkage
    if (prevHash !== lastHash) {
      console.error(`[Verification] Failure: Hash chain broken at line ${i + 1}!`);
      console.error(`  Expected previous hash: ${lastHash}`);
      console.error(`  Found previous hash:    ${prevHash}`);
      chainValid = false;
      break;
    }

    // Recompute Hash to verify no tamper occurred on the message or fields
    const entryData = `${index}|${ts}|${prevHash}|${eventType}|${severity}|${actor}|${subsystem}|${message}`;
    const calculatedHash = crypto.createHash("sha256")
      .update(entryData)
      .digest("hex");

    if (calculatedHash !== currHash) {
      console.error(`[Verification] Failure: Content hash mismatch at line ${i + 1}! (Possible tampering detected)`);
      console.error(`  Stored hash:     ${currHash}`);
      console.error(`  Calculated hash: ${calculatedHash}`);
      chainValid = false;
      break;
    }

    lastHash = currHash;
  }

  if (chainValid) {
    console.log("==================================================================");
    console.log("✓ SUCCESS: Audit log hash chain verification complete!");
    console.log(`✓ Verified ${lines.length} sequential entries.`);
    console.log(`✓ Last chain link signature: ${lastHash}`);
    console.log("==================================================================");
  } else {
    console.error("==================================================================");
    console.error("❌ FAILURE: Audit trail verification FAILED! Integrity compromised.");
    console.error("==================================================================");
    process.exit(1);
  }
}

// Execute direct command-line verification
verifyAuditChain();
