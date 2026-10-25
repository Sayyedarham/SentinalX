import crypto from 'node:crypto';

export const DEFAULT_USER = {
  id: 'usr-analyst-01',
  name: 'Alex Morgan',
  email: 'alex.morgan@sentinalx.dev',
  role: 'Senior Analyst',
  initials: 'AM',
};

export const ROLES = {
  analyst: {
    label: 'Analyst',
    permissions: ['read:incidents', 'read:events', 'investigate', 'propose:response'],
  },
  engineer: {
    label: 'Detection Engineer',
    permissions: ['read:incidents', 'read:events', 'investigate', 'write:detections', 'run:replay'],
  },
  admin: {
    label: 'Administrator',
    permissions: ['read:incidents', 'read:events', 'investigate', 'write:detections', 'run:replay', 'approve:response', 'manage:users'],
  },
};

const now = Date.now();
const iso = (offsetMinutes) => new Date(now - offsetMinutes * 60_000).toISOString();

export const seedEvents = [
  { id: 'evt-1001', timestamp: iso(18), endpointId: 'ws-044', endpointName: 'FIN-LT-044', user: 'j.chen', category: 'process', action: 'process_start', process: 'WINWORD.EXE', parentProcess: 'explorer.exe', commandLine: 'WINWORD.EXE "Q4_Bonus_Adjustment.docm"', risk: 'medium', source: 'sysmon' },
  { id: 'evt-1002', timestamp: iso(17), endpointId: 'ws-044', endpointName: 'FIN-LT-044', user: 'j.chen', category: 'file', action: 'file_write', process: 'WINWORD.EXE', filePath: 'C:\\Users\\j.chen\\AppData\\Local\\Temp\\wd_8F2A.tmp', hash: 'sha256:7e9a...4bc1', risk: 'low', source: 'sysmon' },
  { id: 'evt-1003', timestamp: iso(16), endpointId: 'ws-044', endpointName: 'FIN-LT-044', user: 'j.chen', category: 'process', action: 'process_start', process: 'wscript.exe', parentProcess: 'WINWORD.EXE', commandLine: 'wscript.exe //B C:\\Users\\j.chen\\AppData\\Local\\Temp\\invoice.vbs', risk: 'high', source: 'sysmon' },
  { id: 'evt-1004', timestamp: iso(15), endpointId: 'ws-044', endpointName: 'FIN-LT-044', user: 'j.chen', category: 'network', action: 'dns_query', process: 'wscript.exe', destination: 'cdn-sync-storage.net', destinationIp: '185.199.108.153', port: 443, protocol: 'tls', risk: 'high', source: 'dns' },
  { id: 'evt-1005', timestamp: iso(14), endpointId: 'ws-044', endpointName: 'FIN-LT-044', user: 'j.chen', category: 'process', action: 'process_start', process: 'powershell.exe', parentProcess: 'wscript.exe', commandLine: 'powershell.exe -nop -w hidden -enc SQBFAFgA...', risk: 'critical', source: 'sysmon' },
  { id: 'evt-1006', timestamp: iso(13), endpointId: 'ws-044', endpointName: 'FIN-LT-044', user: 'j.chen', category: 'network', action: 'connection', process: 'powershell.exe', destination: '185.199.108.153', port: 443, protocol: 'tls', bytesOut: 18432, risk: 'critical', source: 'netflow' },
  { id: 'evt-1007', timestamp: iso(11), endpointId: 'ws-044', endpointName: 'FIN-LT-044', user: 'j.chen', category: 'auth', action: 'token_use', process: 'powershell.exe', target: 'AzureAD / Graph API', risk: 'high', source: 'identity' },
  { id: 'evt-1008', timestamp: iso(7), endpointId: 'srv-021', endpointName: 'PAY-API-021', user: 'svc-payments', category: 'process', action: 'process_start', process: 'java.exe', parentProcess: 'services.exe', commandLine: 'java.exe -jar payments.jar', risk: 'low', source: 'sysmon' },
  { id: 'evt-1009', timestamp: iso(5), endpointId: 'ws-019', endpointName: 'ENG-LT-019', user: 'r.patel', category: 'network', action: 'connection', process: 'chrome.exe', destination: 'github.com', port: 443, protocol: 'tls', risk: 'low', source: 'netflow' },
  { id: 'evt-1010', timestamp: iso(2), endpointId: 'ws-032', endpointName: 'HR-LT-032', user: 's.roberts', category: 'file', action: 'file_read', process: 'EXCEL.EXE', filePath: 'C:\\HR\\Benefits\\2026-Open-Enrollment.xlsx', risk: 'low', source: 'sysmon' },
];

export const seedDetections = [
  { id: 'det-001', name: 'Office → Script Interpreter', type: 'rule', status: 'active', severity: 'high', confidence: 0.96, description: 'Detects Office applications spawning script interpreters.', logic: 'parent in [WINWORD.EXE, EXCEL.EXE, POWERPNT.EXE] AND child in [wscript.exe, cscript.exe, powershell.exe]', version: 4, lastUpdated: '2026-10-22', hits: 18, falsePositives: 2 },
  { id: 'det-002', name: 'Encoded PowerShell with Egress', type: 'rule', status: 'active', severity: 'critical', confidence: 0.99, description: 'Flags encoded PowerShell followed by an external TLS connection.', logic: 'commandLine contains -enc AND process = powershell.exe THEN network.destination outside allowlist', version: 7, lastUpdated: '2026-10-23', hits: 7, falsePositives: 0 },
  { id: 'det-003', name: 'Rare Process Lineage', type: 'anomaly', status: 'active', severity: 'medium', confidence: 0.81, description: 'Unsupervised baseline for uncommon parent/child process relationships.', logic: 'lineage rarity score > 0.85 over rolling 30-day baseline', version: 3, lastUpdated: '2026-10-20', hits: 31, falsePositives: 9 },
  { id: 'det-004', name: 'Identity Token from Script Host', type: 'rule', status: 'draft', severity: 'high', confidence: 0.89, description: 'Proposed rule derived from the FIN-LT-044 investigation.', logic: 'script host requests cloud identity token within 10m of Office spawn', version: 1, lastUpdated: '2026-10-24', hits: 0, falsePositives: 0 },
];

export const seedIncidents = [
  {
    id: 'INC-2026-1042',
    title: 'Suspected credential access via malicious macro',
    status: 'investigating',
    severity: 'critical',
    confidence: 0.94,
    endpointId: 'ws-044',
    endpointName: 'FIN-LT-044',
    user: 'j.chen',
    technique: 'T1059.001 · PowerShell',
    firstSeen: iso(18),
    lastSeen: iso(11),
    summary: 'A finance workstation opened a macro-enabled document, launched a VBScript, and executed encoded PowerShell that connected to a newly observed external host.',
    signals: ['Office spawned wscript.exe', 'Encoded PowerShell execution', 'Rare external destination', 'Cloud identity token use'],
    eventIds: ['evt-1001', 'evt-1002', 'evt-1003', 'evt-1004', 'evt-1005', 'evt-1006', 'evt-1007'],
    entities: [
      { label: 'User', value: 'j.chen', kind: 'user' },
      { label: 'Endpoint', value: 'FIN-LT-044', kind: 'endpoint' },
      { label: 'Document', value: 'Q4_Bonus_Adjustment.docm', kind: 'file' },
      { label: 'External host', value: 'cdn-sync-storage.net', kind: 'network' },
    ],
    recommendations: [
      { id: 'rec-01', action: 'Isolate FIN-LT-044 from the network', impact: 'Stops additional egress while preserving host telemetry.', approvalRequired: true, status: 'awaiting_approval' },
      { id: 'rec-02', action: 'Revoke j.chen active cloud sessions', impact: 'Reduces risk of token replay.', approvalRequired: true, status: 'recommended' },
      { id: 'rec-03', action: 'Block cdn-sync-storage.net at DNS layer', impact: 'Prevents recurrence across managed endpoints.', approvalRequired: true, status: 'recommended' },
    ],
  },
  {
    id: 'INC-2026-1039',
    title: 'Unusual service account activity',
    status: 'monitoring',
    severity: 'high',
    confidence: 0.76,
    endpointId: 'srv-021',
    endpointName: 'PAY-API-021',
    user: 'svc-payments',
    technique: 'T1078 · Valid Accounts',
    firstSeen: iso(460),
    lastSeen: iso(34),
    summary: 'The payments service account showed a new execution window outside its learned baseline. No confirmed malicious follow-on activity was found.',
    signals: ['Rare execution window', 'New source subnet', 'No suspicious child process'],
    eventIds: ['evt-1008'],
    entities: [{ label: 'User', value: 'svc-payments', kind: 'user' }, { label: 'Endpoint', value: 'PAY-API-021', kind: 'endpoint' }],
    recommendations: [{ id: 'rec-04', action: 'Review service account schedule', impact: 'Validate the business change before tuning the baseline.', approvalRequired: false, status: 'recommended' }],
  },
];

const clone = (value) => JSON.parse(JSON.stringify(value));

export function createStore() {
  return {
    events: clone(seedEvents),
    detections: clone(seedDetections),
    incidents: clone(seedIncidents),
    audit: [
      { id: 'aud-01', timestamp: iso(12), actor: 'system', action: 'incident.created', target: 'INC-2026-1042', detail: 'Correlated 7 events from FIN-LT-044' },
      { id: 'aud-02', timestamp: iso(10), actor: 'alex.morgan@sentinalx.dev', action: 'investigation.note_added', target: 'INC-2026-1042', detail: 'Marked encoded PowerShell as high-confidence signal' },
      { id: 'aud-03', timestamp: iso(6), actor: 'detection-bot', action: 'rule.proposed', target: 'det-004', detail: 'Generated from confirmed incident evidence' },
    ],
    feedback: [],
    replays: [],
  };
}

export function serializeEvent(event) {
  return {
    ...event,
    timestamp: new Date(event.timestamp).toISOString(),
    displayTime: new Intl.DateTimeFormat('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(new Date(event.timestamp)),
  };
}

export function getDashboard(store) {
  const openIncidents = store.incidents.filter((incident) => incident.status !== 'closed').length;
  const critical = store.incidents.filter((incident) => incident.severity === 'critical' && incident.status !== 'closed').length;
  const highRiskEvents = store.events.filter((event) => ['high', 'critical'].includes(event.risk)).length;
  const healthyEndpoints = new Set(store.events.filter((event) => event.risk === 'low').map((event) => event.endpointId)).size;
  return {
    metrics: [
      { label: 'Open incidents', value: String(openIncidents).padStart(2, '0'), delta: '+1 today', tone: 'critical' },
      { label: 'Critical signals', value: String(critical + 1).padStart(2, '0'), delta: 'Requires review', tone: 'warning' },
      { label: 'Events analyzed', value: '1.24M', delta: '+8.4% vs baseline', tone: 'neutral' },
      { label: 'Endpoints monitored', value: String(healthyEndpoints + 42).padStart(2, '0'), delta: '98.2% healthy', tone: 'success' },
    ],
    signalTrend: [24, 31, 28, 42, 36, 54, 49, 63, 58, 71, 67, 81, 74, 89],
    eventMix: [
      { label: 'Process', value: 45, color: '#8b5cf6' },
      { label: 'Network', value: 28, color: '#06b6d4' },
      { label: 'File', value: 17, color: '#f59e0b' },
      { label: 'Identity', value: 10, color: '#22c55e' },
    ],
    topSignals: store.events.filter((event) => event.risk !== 'low').slice(-5).reverse().map((event) => ({
      id: event.id,
      title: event.action === 'process_start' ? `${event.parentProcess || 'unknown'} → ${event.process}` : `${event.category} activity: ${event.process || event.user}`,
      detail: event.endpointName,
      risk: event.risk,
      time: serializeEvent(event).displayTime,
    })),
    highRiskEvents,
  };
}

export function getIncident(store, incidentId) {
  const incident = store.incidents.find((item) => item.id === incidentId);
  if (!incident) return null;
  return {
    ...incident,
    events: incident.eventIds.map((id) => store.events.find((event) => event.id === id)).filter(Boolean).map(serializeEvent),
    relatedDetections: store.detections.filter((detection) => detection.status === 'active' && (detection.severity === incident.severity || detection.type === 'anomaly')),
  };
}

export function scoreAnomaly(event, store) {
  let score = 0.08;
  if (event.category === 'process' && /powershell|wscript|cscript/i.test(event.process || '')) score += 0.34;
  if (event.parentProcess === 'WINWORD.EXE') score += 0.22;
  if (event.commandLine && /-enc|hidden|nop/i.test(event.commandLine)) score += 0.24;
  if (event.category === 'network' && event.destination && !['github.com', 'microsoft.com'].some((allowed) => event.destination.includes(allowed))) score += 0.18;
  const endpointEvents = store.events.filter((item) => item.endpointId === event.endpointId);
  if (endpointEvents.filter((item) => item.category === event.category).length < 2) score += 0.06;
  return Math.min(0.99, Number(score.toFixed(2)));
}

export function runReplay(store, scenario = 'macro-chain') {
  const relevant = scenario === 'macro-chain' ? store.events.filter((event) => event.endpointId === 'ws-044') : store.events;
  const findings = relevant.map((event) => ({ eventId: event.id, anomalyScore: scoreAnomaly(event, store), matchedRules: store.detections.filter((detection) => detection.status === 'active' && ((detection.id === 'det-001' && event.parentProcess === 'WINWORD.EXE' && event.process === 'wscript.exe') || (detection.id === 'det-002' && /powershell/i.test(event.process || '') && /-enc/i.test(event.commandLine || '')))).map((detection) => detection.id) }));
  const detectionCount = findings.filter((finding) => finding.matchedRules.length || finding.anomalyScore > 0.6).length;
  const replay = { id: `replay-${crypto.randomUUID().slice(0, 8)}`, scenario, createdAt: new Date().toISOString(), eventCount: relevant.length, detectionCount, findings, status: 'completed' };
  store.replays.unshift(replay);
  store.audit.unshift({ id: `aud-${crypto.randomUUID().slice(0, 8)}`, timestamp: replay.createdAt, actor: DEFAULT_USER.email, action: 'replay.completed', target: replay.id, detail: `${detectionCount} findings across ${relevant.length} events` });
  return replay;
}

export function proposeDetection(store, incidentId) {
  const incident = getIncident(store, incidentId);
  if (!incident) return null;
  const detection = {
    id: `det-${String(store.detections.length + 1).padStart(3, '0')}`,
    name: 'Office → Script → Identity Access',
    type: 'rule',
    status: 'draft',
    severity: 'high',
    confidence: 0.91,
    description: `Generated from evidence in ${incident.id}; links Office child process creation to cloud token use.`,
    logic: 'Office child in [wscript.exe, powershell.exe] AND identity token_use within 10m',
    version: 1,
    lastUpdated: new Date().toISOString().slice(0, 10),
    hits: 0,
    falsePositives: 0,
    sourceIncident: incident.id,
  };
  store.detections.unshift(detection);
  store.audit.unshift({ id: `aud-${crypto.randomUUID().slice(0, 8)}`, timestamp: new Date().toISOString(), actor: DEFAULT_USER.email, action: 'rule.proposed', target: detection.id, detail: `Derived from ${incident.id}; draft requires validation` });
  return detection;
}

export function addAudit(store, action, target, detail, actor = DEFAULT_USER.email) {
  store.audit.unshift({ id: `aud-${crypto.randomUUID().slice(0, 8)}`, timestamp: new Date().toISOString(), actor, action, target, detail });
}

export function can(role, permission) {
  return ROLES[role]?.permissions.includes(permission) ?? false;
}
