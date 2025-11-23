import { TrafficLog, PolicyRule, TrafficAction } from '../types';

export const parseWatchGuardXML = async (text: string): Promise<PolicyRule[]> => {
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(text, "text/xml");
  const policies: PolicyRule[] = [];

  const policyNodes = xmlDoc.getElementsByTagName("Policy");
  
  // Basic XML parsing logic simulating WatchGuard XML structure
  // <Policy><Name>HTTP-Proxy</Name><Type>PacketFilter</Type><Action>Allow</Action></Policy>
  for (let i = 0; i < policyNodes.length; i++) {
    const node = policyNodes[i];
    const name = node.getElementsByTagName("Name")[0]?.textContent || `Policy-${i}`;
    const type = node.getElementsByTagName("Type")[0]?.textContent || "Unknown";
    const actionStr = node.getElementsByTagName("Action")[0]?.textContent?.toLowerCase() || "";
    
    let action = TrafficAction.UNKNOWN;
    if (actionStr.includes("allow")) action = TrafficAction.ALLOW;
    else if (actionStr.includes("deny")) action = TrafficAction.DENY;
    else if (actionStr.includes("drop")) action = TrafficAction.DROP;

    policies.push({
      name,
      type,
      action
    });
  }

  // Fallback if no policies found (malformed or different schema), return dummy for demo
  if (policies.length === 0) {
    console.warn("No policies found via standard parsing, attempting broad search or returning empty.");
  }

  return policies;
};

export const parseTrafficCSV = async (text: string, source: 'WatchGuard' | 'Windows'): Promise<TrafficLog[]> => {
  const lines = text.split('\n');
  const logs: TrafficLog[] = [];
  
  if (lines.length < 2) return logs;

  // Detect header to map columns. 
  // Assuming headers: Timestamp, SourceIP, DestIP, DestPort, Protocol, Action
  const headers = lines[0].toLowerCase().split(',').map(h => h.trim());
  
  const idxTime = headers.findIndex(h => h.includes('time'));
  const idxSrc = headers.findIndex(h => h.includes('source') || h.includes('src'));
  const idxDst = headers.findIndex(h => h.includes('dest') || h.includes('dst'));
  const idxPort = headers.findIndex(h => h.includes('port'));
  const idxProto = headers.findIndex(h => h.includes('proto'));
  const idxAction = headers.findIndex(h => h.includes('action'));

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    
    const cols = line.split(',').map(c => c.trim());
    
    // Robustness: skip if missing critical fields
    if (!cols[idxSrc] || !cols[idxDst]) continue;

    let action = TrafficAction.UNKNOWN;
    if (idxAction !== -1 && cols[idxAction]) {
      const act = cols[idxAction].toLowerCase();
      if (act.includes('allow') || act.includes('permit')) action = TrafficAction.ALLOW;
      else if (act.includes('deny') || act.includes('block')) action = TrafficAction.DENY;
      else if (act.includes('drop')) action = TrafficAction.DROP;
    }

    // Default to allow if from Windows logs (usually implies it happened locally) unless specified
    if (source === 'Windows' && action === TrafficAction.UNKNOWN) {
        action = TrafficAction.ALLOW;
    }

    logs.push({
      timestamp: cols[idxTime] || new Date().toISOString(),
      sourceIp: cols[idxSrc] || '0.0.0.0',
      destIp: cols[idxDst] || '0.0.0.0',
      destPort: parseInt(cols[idxPort] || '0', 10),
      protocol: cols[idxProto] || 'TCP',
      action,
      originalSource: source
    });
  }
  
  return logs;
};
