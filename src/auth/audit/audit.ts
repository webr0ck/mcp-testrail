import { appendFileSync } from "node:fs";
import { randomUUID } from "node:crypto";

export const SCHEMA_VERSION = "1.0";

export interface AuditActor {
  user_id: string; // OAuth sub — never empty
  username: string;
}

export interface AuditAuthentication {
  auth_type: string; // always "oauth2"
  auth_required: boolean;
}

export interface AuditRequest {
  request_id: string;
  correlation_id: string;
  client_id: string;
  source_ip: string;
}

export interface AuditRuntime {
  service_name: string;
  container_name: string;
}

export interface AuditEvent {
  schema_version: string;
  event_id: string;
  event_time: string; // ISO-8601 UTC
  event_category: string;
  event_type: string;
  event_outcome: string;
  activity: { tool_name: string };
  actor: AuditActor;
  authentication: AuditAuthentication;
  request: AuditRequest;
  runtime: AuditRuntime;
}

export class AuditLogger {
  constructor(
    private readonly path: string,
    private readonly serviceName: string,
    private readonly containerName: string,
  ) {}

  /**
   * Write a structured JSON audit event to the log file.
   * Events with empty actor.user_id are silently rejected.
   */
  log(event: AuditEvent): void {
    if (!event.actor.user_id) return;
    const line = JSON.stringify(event) + "\n";
    appendFileSync(this.path, line, "utf8");
  }

  newToolCallEvent(
    toolName: string,
    sub: string,
    username: string,
    clientId: string,
    sourceIP: string,
    requestId: string,
    correlationId: string,
    outcome: string,
  ): AuditEvent {
    return {
      schema_version: SCHEMA_VERSION,
      event_id: randomUUID(),
      event_time: new Date().toISOString(),
      event_category: "tool_execution",
      event_type: "tool_call",
      event_outcome: outcome,
      activity: { tool_name: toolName },
      actor: { user_id: sub, username },
      authentication: { auth_type: "oauth2", auth_required: true },
      request: {
        request_id: requestId,
        correlation_id: correlationId,
        client_id: clientId,
        source_ip: sourceIP,
      },
      runtime: {
        service_name: this.serviceName,
        container_name: this.containerName,
      },
    };
  }
}
