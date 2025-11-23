import { TrafficLog, PolicyRule, AuditSummary, BlindSpot, PolicyViolation, TrafficAction } from '../types';

const generateFlowSignature = (log: TrafficLog): string => {
  return `${log.sourceIp}|${log.destIp}|${log.destPort}|${log.protocol}`;
};

export const performAudit = (
  policies: PolicyRule[],
  wgLogs: TrafficLog[],
  winLogs: TrafficLog[]
): AuditSummary => {
  
  const blindSpots: BlindSpot[] = [];
  const violations: PolicyViolation[] = [];

  // 1. Index WatchGuard Logs for O(1) lookup
  const wgSignatures = new Set<string>();
  wgLogs.forEach(log => {
    wgSignatures.add(generateFlowSignature(log));
  });

  // 2. Identify Blind Spots: Traffic seen on Windows (Endpoint) but NOT on WatchGuard (Gateway)
  // This suggests lateral movement within the LAN that didn't hit the gateway, or bypass.
  winLogs.forEach(winLog => {
    const sig = generateFlowSignature(winLog);
    if (!wgSignatures.has(sig)) {
      blindSpots.push({
        flowId: sig,
        windowsLog: winLog,
        description: `Traffic from ${winLog.sourceIp} to ${winLog.destIp}:${winLog.destPort} seen on Endpoint but not Gateway.`
      });
    }
  });

  // 3. Identify Policy Violations in WatchGuard Logs
  // Logic: If a log says "Allow", but the policy for that port/proto says "Deny" (mock logic)
  // Real world requires complex subnet matching. Here we do simple heuristic matching.
  
  // Create a simplified policy map: "Port:Protocol" -> Action
  const policyMap = new Map<string, TrafficAction>();
  policies.forEach(p => {
    // Attempt to infer port/proto from name if explicit fields aren't parsed deeply in this demo
    // E.g. "HTTP-Proxy" implies 80/TCP. 
    // For this demo, we assume the XML might contain specific rule definitions or we're generic.
    // We will just look for explicit mismatches where WG log says ALLOW but we flag it as suspicious based on common ports.
  });

  // Simplified violation detection for demo:
  // 1. Inbound RDP/SSH/Telnet from public IPs allowed
  // 2. Any explicit DENY in logs is just a log entry, not a violation of policy (policy worked).
  //    A violation is TRAFFIC ALLOWED that SHOULD BE BLOCKED.
  
  wgLogs.forEach(log => {
    if (log.action === TrafficAction.ALLOW) {
      const isPublicSource = !log.sourceIp.startsWith('192.168.') && !log.sourceIp.startsWith('10.');
      
      // Heuristic 1: Inbound Management Ports from Public Internet
      if (isPublicSource && [3389, 22, 23].includes(log.destPort)) {
        violations.push({
          flowId: generateFlowSignature(log),
          log,
          description: `High Risk: Allowed inbound management traffic (${log.destPort}) from public IP ${log.sourceIp}.`
        });
      }

      // Heuristic 2: Telnet Usage
      if (log.destPort === 23) {
        violations.push({
          flowId: generateFlowSignature(log),
          log,
          description: `Legacy Protocol: Cleartext Telnet traffic allowed.`
        });
      }
    }
  });

  return {
    totalWatchGuardLogs: wgLogs.length,
    totalWindowsLogs: winLogs.length,
    blindSpots,
    violations,
    policyCount: policies.length
  };
};
