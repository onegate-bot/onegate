/** Shared domain types. */

export type Effect = "allow" | "deny";
export type DefaultPolicy = "allow-all" | "deny-unmatched";
export type RuleScope = "agent" | "project";

export interface Agent {
  id: string;
  name: string;
  tokenHash: string;
  projectId: string | null;
  defaultPolicy: DefaultPolicy;
  createdAt: string;
}

export interface Project {
  id: string;
  name: string;
  createdAt: string;
}

export interface Credential {
  id: string;
  integrationId: string;
  name: string;
  /** Integration-specific secret material, e.g. { pat } or { refreshToken }. */
  data: Record<string, string>;
  createdAt: string;
}

export interface Rule {
  id: string;
  scope: RuleScope;
  /** Agent id or project id, depending on scope. */
  subjectId: string;
  /** Integration id this rule applies to, or "*" for all. */
  integrationId: string;
  /** Uppercase HTTP methods, or ["*"]. */
  methods: string[];
  /** Glob over the URL path: `*` = one segment, `**` = anything. */
  pathGlob: string;
  effect: Effect;
  createdAt: string;
  /**
   * Access lease (time-boxed allow). When set, this allow rule stops granting
   * access once `expiresAt` passes: the policy engine treats it as LAPSED, which
   * falls to a default-deny that the proxy turns into an owner renewal prompt.
   * Null = no lease (never expires). Only meaningful on allow rules.
   */
  expiresAt?: string | null;
  /**
   * The lease duration (seconds) resolved when this rule was last stamped.
   * Used to re-stamp `expiresAt` on a one-tap renewal without re-entering the
   * credential. Null = no lease.
   */
  leaseTtlSeconds?: number | null;
}

export type ConnectionKind = "app" | "llm";
export type LlmStrategy = "fallback" | "round-robin";

/**
 * A named credential. Connections let a vendor hold MANY credentials at once.
 *
 * - kind "llm" (vendor anthropic|openai|gemini): the per-agent LLM routing
 *   engine picks one per request. Always tenant-wide (ownerAgentId null).
 * - kind "app" (vendor = the integration id, e.g. github|slack): multiple
 *   named accounts for one app integration. A connection is either tenant-wide
 *   (ownerAgentId null, available to every agent) or agent-bound (ownerAgentId
 *   set, available only to that agent). Per-request account selection is done
 *   with the `x-onegate-connection` request header, else the agent's saved
 *   default (agent_app_config), else the tenant-wide default, else the legacy
 *   single `credentials` row.
 *
 * Exactly one default per (kind, vendor, owner-bucket): the tenant-wide bucket
 * (ownerAgentId null) has its own default and each agent-owned bucket has its
 * own default, enforced by the store.
 */
export interface Connection {
  id: string;
  kind: ConnectionKind;
  /** For llm: the vendor id (anthropic|openai|gemini). For app: the integration id. */
  vendor: string;
  /** User label, e.g. "Anthropic - prod". */
  name: string;
  /**
   * Vendor-specific secret material. anthropic/gemini: { apiKey }.
   * openai: { apiKey } or an imported auth.json shape
   * { accessToken, accountId? } (Codex-CLI style). App connections carry the
   * same fields the integration's credentialFields declare.
   */
  data: Record<string, string>;
  /**
   * App connections only: the agent this account is bound to, or null for a
   * tenant-wide (shared) account. Always null for llm connections.
   */
  ownerAgentId: string | null;
  /** Exactly one default per (kind, vendor, owner-bucket), enforced by the store. */
  isDefault: boolean;
  /**
   * The owner's access-lease override chosen at connect time, for time-boxed
   * integrations. NULL = inherit the integration default. 0 = always-on
   * (infinite time box, i.e. not time-boxed at all). >0 = custom lease seconds.
   * Non-time-boxed integrations leave this null and get no lease.
   */
  leaseTtlSeconds?: number | null;
  createdAt: string;
  updatedAt: string;
}

/**
 * Marks an integration as time-boxed by default: any allow rule that connects
 * it gets an access lease of `ttlSeconds`. Presence of the row = time-boxed;
 * absence = a regular (non-time-boxed) integration. The owner can override the
 * duration per connection at connect time (Connection.leaseTtlSeconds).
 */
export interface IntegrationLease {
  integrationId: string;
  ttlSeconds: number;
  updatedAt: string;
}

/**
 * Per-agent saved choice of which app connection to use for an integration
 * when no `x-onegate-connection` header is sent. Absent = fall through to the
 * tenant-wide default app connection, then the legacy credentials row.
 */
export interface AgentAppConfig {
  agentId: string;
  integrationId: string;
  connectionId: string;
  updatedAt: string;
}

/** Per-agent LLM routing configuration. Absent or disabled = passthrough-as-today. */
export interface AgentLlmConfig {
  agentId: string;
  enabled: boolean;
  strategy: LlmStrategy;
  /** Ordered connection ids. Order is the fallback order. */
  connectionIds: string[];
  updatedAt: string;
}

/** Persisted strategy counters, one row per (agent, vendor). */
export interface LlmStrategyState {
  agentId: string;
  vendor: string;
  /** Fallback: index of the connection currently in use. */
  activeIndex: number;
  /** Round-robin: index of the most recently selected connection (-1 = none yet). */
  rrCursor: number;
  /** Fallback: calls served on a non-primary connection since the last switch. */
  callsSinceFallback: number;
  /** Round-robin: connectionId -> remaining skip count. */
  cooldowns: Record<string, number>;
  updatedAt: string;
}

/** One selection event in the llm_usage log (also rolled up for counters). */
export interface LlmUsageEvent {
  id: number;
  ts: string;
  connectionId: string;
  connectionName: string | null;
  agentId: string | null;
  vendor: string | null;
  strategy: LlmStrategy | null;
  requests: number;
  errors: number;
  inputTokens: number | null;
  outputTokens: number | null;
  /** 1 when this row records a routing selection (vs a pure rollup row). */
  selected: boolean;
  /** 1 when this attempt was the in-request failover retry. */
  failover: boolean;
  status: number | null;
}

/**
 * A self-service connect-wizard link. An operator (or a bot) mints one of these
 * scoped to a single agent and a single integration. The bot owner opens the
 * link, brings their own OAuth app, runs consent, and OneGate auto-wires the
 * connection, grant and allow rule. Single-use, expiring, unguessable.
 */
export interface OnboardingLink {
  /** Unguessable token, randomBytes(24).toString("base64url"). */
  token: string;
  /** The single agent the connection will be granted to. */
  agentId: string;
  /** The single integration (google | slack | jira | ...). */
  integrationId: string;
  /** Optional preset requested scope ids. */
  scopes: string[] | null;
  /** Optional preset display name for the connection. */
  connectionName: string | null;
  createdAt: string;
  expiresAt: string;
  /** Set when consent completes. A used link is no longer valid. */
  usedAt: string | null;
  /**
   * Set for a RENEWAL link: the allow rule whose lease this link re-stamps.
   * A renewal link opens a one-tap renew page (no credential re-entry) instead
   * of the connect wizard. Null = a normal connect link.
   */
  ruleId?: string | null;
}

export type Decision =
  | "allow"
  | "deny"
  | "passthrough"
  | "auth_failed"
  | "no_credential"
  | "unknown_connection"
  | "connection_not_granted"
  | "body_too_large";

export interface AuditEntry {
  id: number;
  ts: string;
  agentId: string | null;
  agentName: string | null;
  integrationId: string | null;
  host: string;
  method: string | null;
  path: string | null;
  decision: Decision;
  ruleId: string | null;
  status: number | null;
  /**
   * Derived on read (see audit-meta.ts), not stored. "onegate" means OneGate
   * itself blocked the request; "upstream" means it was allowed/passed through
   * and the status came from the API.
   */
  source: "onegate" | "upstream";
  /** Derived plain-words explanation, or null when none adds value. */
  reason: string | null;
  /** LLM routing fields, set on strategy-routed requests, null otherwise. */
  connectionId: string | null;
  connectionName: string | null;
  llmVendor: string | null;
  llmStrategy: LlmStrategy | null;
  llmFailover: boolean | null;
}

/** Status values for an owner_notifications row. */
export type OwnerNotificationStatus = "pending" | "delivered" | "failed" | "suppressed";

/**
 * A record of an attempted (or in-flight) proactive owner notification.
 * Created when a proxy deny triggers and the agent has a notify webhook set.
 * Deduped per (agentId, integrationId) within a configurable window so the
 * same deny event does not spam.
 */
export interface OwnerNotification {
  id: number;
  agentId: string;
  integrationId: string;
  /** The onboarding link token that was minted for this notification, if any. */
  connectToken: string | null;
  status: OwnerNotificationStatus;
  createdAt: string;
  deliveredAt: string | null;
  lastAttemptAt: string | null;
  attempts: number;
  error: string | null;
  /**
   * Custom dedup key. When set (e.g. a lease lapse `lease:<ruleId>:<expiresAt>`)
   * dedup is keyed on this exact string instead of the (agent, integration) time
   * window, so each distinct lapse always reaches the owner but repeated
   * requests within one lapse do not spam.
   */
  dedupKey?: string | null;
}
