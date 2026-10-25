import test from 'node:test';
import assert from 'node:assert/strict';
import { createStore, getDashboard, getIncident, proposeDetection, runReplay, scoreAnomaly, can } from '../src/platform.js';

test('dashboard summarizes active incidents and telemetry', () => {
  const store = createStore();
  const dashboard = getDashboard(store);
  assert.equal(dashboard.metrics.length, 4);
  assert.equal(dashboard.metrics[0].value, '02');
  assert.equal(dashboard.eventMix.reduce((sum, item) => sum + item.value, 0), 100);
  assert.ok(dashboard.signalTrend.length >= 10);
});

test('incident reconstruction returns evidence in event order', () => {
  const store = createStore();
  const incident = getIncident(store, 'INC-2026-1042');
  assert.equal(incident.events.length, 7);
  assert.equal(incident.events[0].id, 'evt-1001');
  assert.match(incident.summary, /macro-enabled document/i);
  assert.ok(incident.recommendations.some((item) => item.approvalRequired));
});

test('anomaly scoring ranks encoded PowerShell above benign browser traffic', () => {
  const store = createStore();
  const suspicious = store.events.find((event) => event.id === 'evt-1005');
  const benign = store.events.find((event) => event.id === 'evt-1009');
  assert.ok(scoreAnomaly(suspicious, store) > scoreAnomaly(benign, store));
  assert.ok(scoreAnomaly(suspicious, store) >= 0.6);
});

test('replay evaluates scenario and records an audit entry', () => {
  const store = createStore();
  const replay = runReplay(store, 'macro-chain');
  assert.equal(replay.status, 'completed');
  assert.equal(replay.eventCount, 7);
  assert.ok(replay.detectionCount > 0);
  assert.equal(store.replays[0].id, replay.id);
  assert.ok(store.audit.some((item) => item.target === replay.id));
});

test('detection proposals preserve incident provenance', () => {
  const store = createStore();
  const detection = proposeDetection(store, 'INC-2026-1042');
  assert.equal(detection.status, 'draft');
  assert.equal(detection.sourceIncident, 'INC-2026-1042');
  assert.ok(store.audit.some((item) => item.target === detection.id && item.action === 'rule.proposed'));
});

test('role permissions protect disruptive actions and engineering workflows', () => {
  assert.equal(can('analyst', 'approve:response'), false);
  assert.equal(can('admin', 'approve:response'), true);
  assert.equal(can('engineer', 'run:replay'), true);
  assert.equal(can('analyst', 'read:events'), true);
});
