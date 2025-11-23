export enum TrafficAction {
  ALLOW = 'Allow',
  DENY = 'Deny',
  DROP = 'Drop',
  UNKNOWN = 'Unknown'
}

export interface TrafficLog {
  timestamp: string;
  sourceIp: string;
  destIp: string;
  destPort: number;
  protocol: string;
  action: TrafficAction;
  originalSource: 'WatchGuard' | 'Windows';
}

export interface PolicyRule {
  name: string;
  type: string;
  action: TrafficAction;
  // Simplified for demo: assume rules apply broadly or we parse generic sources
  description?: string;
}

export interface BlindSpot {
  flowId: string; // Signature
  windowsLog: TrafficLog;
  description: string;
}

export interface PolicyViolation {
  flowId: string;
  log: TrafficLog;
  violatedPolicy?: PolicyRule;
  description: string;
}

export interface AuditSummary {
  totalWatchGuardLogs: number;
  totalWindowsLogs: number;
  blindSpots: BlindSpot[];
  violations: PolicyViolation[];
  policyCount: number;
}
