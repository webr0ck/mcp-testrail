import { describe, it, expect } from "vitest";
import { writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { AuditLogger, SCHEMA_VERSION } from "../../../src/auth/audit/audit.js";

function tempLogPath(): string {
  return join(tmpdir(), `audit-test-${randomUUID()}.log`);
}

describe("AuditLogger", () => {
  it("writes and reads back a tool call event", () => {
    const path = tempLogPath();
    writeFileSync(path, ""); // create empty file

    const logger = new AuditLogger(path, "mcp-testrail", "test-container");
    const event = logger.newToolCallEvent(
      "getProjects",
      "sub-123",
      "alice",
      "client-1",
      "10.0.0.1",
      "req-uuid",
      "corr-uuid",
      "success",
    );
    logger.log(event);

    const lines = readFileSync(path, "utf8").trim().split("\n");
    expect(lines).toHaveLength(1);

    const parsed = JSON.parse(lines[0]);
    expect(parsed.schema_version).toBe(SCHEMA_VERSION);
    expect(parsed.actor.user_id).toBe("sub-123");
    expect(parsed.actor.username).toBe("alice");
    expect(parsed.authentication.auth_type).toBe("oauth2");
    expect(parsed.authentication.auth_required).toBe(true);
    expect(parsed.event_type).toBe("tool_call");
    expect(parsed.activity.tool_name).toBe("getProjects");
    expect(parsed.runtime.service_name).toBe("mcp-testrail");
  });

  it("rejects events with empty actor.user_id", () => {
    const path = tempLogPath();
    writeFileSync(path, "");

    const logger = new AuditLogger(path, "mcp-testrail", "c");
    const event = logger.newToolCallEvent(
      "getCases",
      "", // empty sub — must be rejected
      "alice",
      "cli",
      "127.0.0.1",
      "r",
      "c",
      "success",
    );
    logger.log(event);

    const content = readFileSync(path, "utf8");
    expect(content).toBe(""); // nothing written
  });

  it("writes multiple events as separate JSON lines", () => {
    const path = tempLogPath();
    writeFileSync(path, "");

    const logger = new AuditLogger(path, "mcp-testrail", "c");
    for (let i = 0; i < 3; i++) {
      logger.log(
        logger.newToolCallEvent(
          "getRuns",
          "sub-1",
          "user",
          "cli",
          "127.0.0.1",
          `req-${i}`,
          `corr-${i}`,
          "success",
        ),
      );
    }

    const lines = readFileSync(path, "utf8").trim().split("\n");
    expect(lines).toHaveLength(3);
  });

  it("event_time is UTC (ends with Z)", () => {
    const path = tempLogPath();
    writeFileSync(path, "");

    const logger = new AuditLogger(path, "mcp-testrail", "c");
    logger.log(
      logger.newToolCallEvent("t", "sub-1", "u", "c", "ip", "r", "c", "success"),
    );

    const line = readFileSync(path, "utf8").trim();
    const parsed = JSON.parse(line);
    expect(parsed.event_time.endsWith("Z")).toBe(true);
  });
});
