import http from 'node:http';
import { createStore, DEFAULT_USER, ROLES, addAudit, can, getDashboard, getIncident, proposeDetection, runReplay, serializeEvent } from './platform.js';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const publicDir = join(root, 'public');
const store = createStore();
const PORT = Number(process.env.PORT || 4173);

const send = (res, status, data, headers = {}) => {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  res.end(JSON.stringify(data));
};

const sendText = (res, status, data, contentType) => {
  res.writeHead(status, { 'Content-Type': contentType });
  res.end(data);
};

async function body(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  if (!chunks.length) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return {}; }
}

function actor(req) {
  const role = req.headers['x-sentinalx-role'] || 'admin';
  return { role, email: req.headers['x-sentinalx-user'] || DEFAULT_USER.email };
}

function authorized(req, permission) {
  return can(actor(req).role, permission);
}

async function api(req, res, pathname) {
  if (pathname === '/api/health') return send(res, 200, { status: 'ok', service: 'sentinalx-api', version: '1.0.0' });
  if (pathname === '/api/me') return send(res, 200, { ...DEFAULT_USER, role: ROLES[actor(req).role]?.label || DEFAULT_USER.role, permissions: ROLES[actor(req).role]?.permissions || [] });
  if (!authorized(req, 'read:incidents') && pathname.startsWith('/api/')) return send(res, 403, { error: 'forbidden', message: 'This role does not have access to the requested resource.' });

  if (req.method === 'GET' && pathname === '/api/dashboard') return send(res, 200, getDashboard(store));
  if (req.method === 'GET' && pathname === '/api/incidents') return send(res, 200, { items: store.incidents, total: store.incidents.length });
  if (req.method === 'GET' && pathname.startsWith('/api/incidents/')) {
    const incident = getIncident(store, pathname.split('/').pop());
    return incident ? send(res, 200, incident) : send(res, 404, { error: 'not_found' });
  }
  if (req.method === 'GET' && pathname === '/api/events') return send(res, 200, { items: store.events.map(serializeEvent), total: store.events.length });
  if (req.method === 'GET' && pathname === '/api/detections') return send(res, 200, { items: store.detections, total: store.detections.length });
  if (req.method === 'GET' && pathname === '/api/audit') return send(res, 200, { items: store.audit, total: store.audit.length });
  if (req.method === 'GET' && pathname === '/api/replays') return send(res, 200, { items: store.replays, total: store.replays.length });
  if (req.method === 'POST' && pathname === '/api/replays') {
    if (!authorized(req, 'run:replay')) return send(res, 403, { error: 'forbidden' });
    const payload = await body(req);
    return send(res, 201, runReplay(store, payload.scenario || 'macro-chain'));
  }
  if (req.method === 'POST' && pathname.endsWith('/propose-detection')) {
    if (!authorized(req, 'write:detections')) return send(res, 403, { error: 'forbidden' });
    const incidentId = pathname.split('/')[3];
    const detection = proposeDetection(store, incidentId);
    return detection ? send(res, 201, detection) : send(res, 404, { error: 'incident_not_found' });
  }
  if (req.method === 'POST' && pathname.endsWith('/feedback')) {
    if (!authorized(req, 'investigate')) return send(res, 403, { error: 'forbidden' });
    const incidentId = pathname.split('/')[3];
    const payload = await body(req);
    const incident = store.incidents.find((item) => item.id === incidentId);
    if (!incident) return send(res, 404, { error: 'incident_not_found' });
    store.feedback.unshift({ id: `fb-${Date.now()}`, incidentId, label: payload.label || 'confirmed', note: payload.note || '', createdAt: new Date().toISOString(), actor: actor(req).email });
    addAudit(store, 'feedback.recorded', incidentId, `Analyst marked incident ${payload.label || 'confirmed'}`);
    return send(res, 201, store.feedback[0]);
  }
  if (req.method === 'POST' && pathname.includes('/recommendations/') && pathname.endsWith('/approve')) {
    if (!authorized(req, 'approve:response')) return send(res, 403, { error: 'forbidden' });
    const pathParts = pathname.split('/');
    const incidentId = pathParts[3];
    const recId = pathParts[5];
    const incident = store.incidents.find((item) => item.id === incidentId);
    const recommendation = incident?.recommendations.find((item) => item.id === recId);
    if (!recommendation) return send(res, 404, { error: 'recommendation_not_found' });
    recommendation.status = 'approved';
    recommendation.approvedAt = new Date().toISOString();
    addAudit(store, 'response.approved', incidentId, `Approved: ${recommendation.action}`);
    return send(res, 200, recommendation);
  }
  return send(res, 404, { error: 'not_found' });
}

async function staticFile(res, pathname) {
  const safePath = normalize(pathname === '/' ? '/index.html' : pathname).replace(/^([/\\])+/, '');
  const path = join(publicDir, safePath);
  if (!path.startsWith(publicDir)) return sendText(res, 403, 'Forbidden', 'text/plain');
  try {
    const content = await readFile(path);
    const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml' };
    sendText(res, 200, content, types[extname(path)] || 'application/octet-stream');
  } catch { sendText(res, 404, 'Not found', 'text/plain'); }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  try {
    if (url.pathname.startsWith('/api/')) await api(req, res, url.pathname);
    else await staticFile(res, url.pathname);
  } catch (error) {
    console.error(error);
    send(res, 500, { error: 'internal_error', message: 'Unexpected server error.' });
  }
});

server.listen(PORT, () => console.log(`SentinalX running at http://localhost:${PORT}`));
