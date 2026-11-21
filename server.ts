import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { exportCsv, exportJson, generateMispEvent, generateTakedownReport } from './src/server/exporters.ts';
import {
  buildCampaignClusters,
  buildGeoData,
  buildOsintMatrix,
  calculateAggregateImpact,
  getBrandDna,
  getDriftStatus,
  getHistoricalTimeline,
  getOsintIntel,
  getPrecrimeRisk,
} from './src/server/intel.ts';
import { isValidDomainInput, toAscii } from './src/server/normalize.ts';
import { generateCandidates } from './src/server/permutations.ts';
import { DynamicResolver } from './src/server/resolver.ts';
import { analyzeCandidate } from './src/server/scoring.ts';
import { sortFindings, tierCounts } from './src/server/triage.ts';
import type {
  EnrichedFindingSchema,
  Finding,
  FindingStatus,
  ScanRequest,
  ScanResults,
  ScanState,
} from './src/server/types.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ALLOWED_CHANNELS = new Set([
  'Domain Registrar',
  'Hosting Provider',
  'Google Safe Browsing',
  'Microsoft Defender SmartScreen',
  'APWG',
  'National CERT / CSIRT',
]);
const MAX_JOBS = 40;

interface ScanJob {
  scan_id: string;
  request: ScanRequest;
  state: ScanState;
  progress_pct: number;
  current_step: string;
  domains_total: number;
  domains_processed: number;
  findings_so_far: number;
  results: ScanResults | null;
  error: string | null;
  started_at: string;
  updated_at: string;
  completed_at: string | null;
}

const scanJobs = new Map<string, ScanJob>();

function pruneOldJobs(): void {
  while (scanJobs.size >= MAX_JOBS) {
    const oldestKey = scanJobs.keys().next().value;
    if (!oldestKey) break;
    scanJobs.delete(oldestKey);
  }
}

function toEnrichedSchema(
  f: Finding,
  brand: string,
  scanPass: number,
  onlineEnrich: boolean
): EnrichedFindingSchema {
  const dna = getBrandDna(brand, f, scanPass);
  const precrime = getPrecrimeRisk(f);
  const { drift, driftData } = getDriftStatus(f, scanPass);
  const osint = getOsintIntel(brand, f, onlineEnrich);
  const timeline = getHistoricalTimeline(f);
  const osintMatrix = buildOsintMatrix(brand, f);

  const isLive = Boolean(f.facts && f.facts.is_live);
  let status: FindingStatus;
  if (drift) status = 'DRIFT DETECTED';
  else if (precrime !== null) status = 'PRECRIME';
  else if (isLive) status = 'LIVE INFRA';
  else status = 'UNRESOLVED';

  return {
    brand,
    domain: f.domain,
    candidate: f.candidate,
    facts: f.facts,
    signals: f.signals,
    tier: f.tier,
    score: f.score,
    similarity_pct: f.similarity_pct,
    mutation_type: f.mutation_type,
    status,
    osint,
    osint_matrix: osintMatrix,
    timeline,
    dna,
    precrime,
    drift,
    drift_data: driftData,
    enrichment: onlineEnrich ? f.enrichment ?? null : null,
  };
}

function selectLivePrioritySet(domains: string[]): Set<string> {
  // Prioritize key attack classes cleanly within LIVE_CAP=8 when Live Enrich is enabled
  const selected = new Set<string>();
  const prioritySuffixes = ['.com', '.net', '.org', '.co', '.xyz'];
  for (const d of domains) {
    if (selected.size >= DynamicResolver.LIVE_CAP) break;
    if (prioritySuffixes.some((s) => d.endsWith(s))) {
      selected.add(d);
    }
  }
  for (const d of domains) {
    if (selected.size >= DynamicResolver.LIVE_CAP) break;
    selected.add(d);
  }
  return selected;
}

async function runScanJob(scanId: string): Promise<void> {
  const job = scanJobs.get(scanId);
  if (!job) return;

  try {
    const req = job.request;
    job.state = 'running';
    job.started_at = new Date().toISOString();
    job.updated_at = job.started_at;
    job.current_step = 'generating candidates';

    const resolver = new DynamicResolver(req.online_enrich);
    const candidates = generateCandidates(req.brand, 2000);
    const allowlist = new Set(req.allowlist.map((n) => toAscii(n).toLowerCase()));
    allowlist.add(toAscii(req.brand).toLowerCase());

    job.domains_total = candidates.length;
    job.updated_at = new Date().toISOString();

    let liveSet: Set<string> | null = null;
    if (req.online_enrich) {
      const highValue = candidates
        .filter((c) => c.weight >= 70 && !allowlist.has(c.registrable.toLowerCase()))
        .map((c) => c.registrable);
      liveSet = selectLivePrioritySet(highValue);
    }

    const findings: Finding[] = [];
    for (let i = 0; i < candidates.length; i++) {
      const c = candidates[i];
      if (allowlist.has(c.registrable.toLowerCase())) {
        continue;
      }

      job.current_step = `analyzing ${c.registrable}`;
      job.domains_processed = i + 1;
      job.progress_pct = Math.floor(((i + 1) / Math.max(1, candidates.length)) * 100);
      if (i % 50 === 0 || i === candidates.length - 1) {
        job.updated_at = new Date().toISOString();
      }

      const shouldResolveLive = !req.online_enrich || Boolean(liveSet?.has(c.registrable));
      const { facts, enrichment } = shouldResolveLive
        ? await resolver.resolve(c.registrable, c.registrable)
        : { facts: null, enrichment: null };

      const finding = analyzeCandidate(
        req.brand,
        c,
        facts,
        allowlist,
        req.online_enrich ? enrichment : null
      );
      if (finding) {
        findings.push(finding);
        job.findings_so_far = findings.length;
      }
    }

    job.current_step = 'enriching findings';
    job.updated_at = new Date().toISOString();

    const ordered = sortFindings(findings);
    const geo = buildGeoData(ordered);
    const clusters = buildCampaignClusters(ordered);
    const impact = calculateAggregateImpact(ordered);
    const findingSchemas = ordered.map((f) =>
      toEnrichedSchema(f, req.brand, req.scan_pass, req.online_enrich)
    );

    const completedAt = new Date().toISOString();
    job.results = {
      scan_id: scanId,
      brand: req.brand,
      scan_pass: req.scan_pass,
      online_enrich: req.online_enrich,
      inspect_websites: req.inspect_websites,
      generated: candidates.length,
      tiers: tierCounts(ordered),
      impact,
      findings: findingSchemas,
      geo,
      clusters,
      completed_at: completedAt,
    };

    job.state = 'complete';
    job.progress_pct = 100;
    job.current_step = 'complete';
    job.completed_at = completedAt;
    job.updated_at = completedAt;
  } catch (err) {
    job.state = 'failed';
    job.error = err instanceof Error ? err.message : 'Scan execution failed';
    job.updated_at = new Date().toISOString();
  }
}

async function startServer(): Promise<void> {
  const app = express();
  app.use(express.json({ limit: '256kb' }));

  app.post('/api/scan', (req, res) => {
    const body = (req.body ?? {}) as Partial<ScanRequest>;
    const rawBrand = typeof body.brand === 'string' ? body.brand.trim() : '';
    const brand = rawBrand || 'acmecorp.com';
    if (!isValidDomainInput(brand)) {
      res.status(400).json({ detail: 'Invalid brand domain format' });
      return;
    }

    const scanPass = body.scan_pass === 2 ? 2 : 1;
    const onlineEnrich = Boolean(body.online_enrich);
    const inspectWebsites = Boolean(body.inspect_websites);
    const allowlist = Array.isArray(body.allowlist)
      ? body.allowlist.filter((item): item is string => typeof item === 'string' && isValidDomainInput(item)).slice(0, 50)
      : [];

    pruneOldJobs();
    const scanId = randomUUID();
    const now = new Date().toISOString();
    const job: ScanJob = {
      scan_id: scanId,
      request: {
        brand,
        scan_pass: scanPass,
        online_enrich: onlineEnrich,
        inspect_websites: inspectWebsites,
        allowlist,
      },
      state: 'pending',
      progress_pct: 0,
      current_step: 'initializing',
      domains_total: 0,
      domains_processed: 0,
      findings_so_far: 0,
      results: null,
      error: null,
      started_at: now,
      updated_at: now,
      completed_at: null,
    };
    scanJobs.set(scanId, job);

    // Kick off scan asynchronously so status polling reflects real progress
    setTimeout(() => {
      void runScanJob(scanId);
    }, 10);

    res.json({
      scan_id: scanId,
      status: 'pending',
      message: 'Scan started. Poll /api/scan/{scan_id}/status for progress.',
    });
  });

  app.get('/api/scan/:scanId/status', (req, res) => {
    const { scanId } = req.params;
    if (!UUID_RE.test(scanId)) {
      res.status(400).json({ detail: 'Invalid scan_id' });
      return;
    }
    const job = scanJobs.get(scanId);
    if (!job) {
      res.status(404).json({ detail: 'Scan not found' });
      return;
    }
    res.json({
      scan_id: job.scan_id,
      status: job.state,
      progress_pct: job.progress_pct,
      current_step: job.current_step,
      domains_total: job.domains_total,
      domains_processed: job.domains_processed,
      findings_so_far: job.findings_so_far,
      started_at: job.started_at,
      updated_at: job.updated_at,
      error: job.error,
    });
  });

  app.get('/api/scan/:scanId/results', (req, res) => {
    const { scanId } = req.params;
    if (!UUID_RE.test(scanId)) {
      res.status(400).json({ detail: 'Invalid scan_id' });
      return;
    }
    const job = scanJobs.get(scanId);
    if (!job) {
      res.status(404).json({ detail: 'Scan not found' });
      return;
    }
    if (job.state !== 'complete') {
      res.status(409).json({ detail: `Scan not complete (state: ${job.state})` });
      return;
    }
    if (!job.results) {
      res.status(500).json({ detail: 'Scan complete but no results' });
      return;
    }
    res.json(job.results);
  });

  app.get('/api/export/csv', (req, res) => {
    const scanId = typeof req.query.scan_id === 'string' ? req.query.scan_id : '';
    if (!UUID_RE.test(scanId)) {
      res.status(400).send('Invalid scan_id');
      return;
    }
    const job = scanJobs.get(scanId);
    if (!job || !job.results) {
      res.status(404).send('No scan data available');
      return;
    }
    const csv = exportCsv(job.results.findings);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename=proteus_triage_${scanId}.csv`
    );
    res.send(csv);
  });

  app.get('/api/export/json', (req, res) => {
    const scanId = typeof req.query.scan_id === 'string' ? req.query.scan_id : '';
    if (!UUID_RE.test(scanId)) {
      res.status(400).send('Invalid scan_id');
      return;
    }
    const job = scanJobs.get(scanId);
    if (!job || !job.results) {
      res.status(404).send('No scan data available');
      return;
    }
    const jsonText = exportJson(job.results.findings, job.results.brand);
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename=proteus_triage_${scanId}.json`
    );
    res.send(jsonText);
  });

  app.get('/api/export/misp/:domain', (req, res) => {
    const scanId = typeof req.query.scan_id === 'string' ? req.query.scan_id : '';
    const domain = req.params.domain;
    if (!UUID_RE.test(scanId)) {
      res.status(400).send('Invalid scan_id');
      return;
    }
    const job = scanJobs.get(scanId);
    if (!job || !job.results) {
      res.status(404).send('No scan data available');
      return;
    }
    const match = job.results.findings.find(
      (f) => f.candidate.domain === domain || f.candidate.ascii_form === domain
    );
    if (!match) {
      res.status(404).json({ detail: 'Domain not found in current scan' });
      return;
    }
    const misp = generateMispEvent(match);
    const safeDomain = match.candidate.ascii_form.replace(/[^a-zA-Z0-9-]/g, '_');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename=proteus_misp_${safeDomain}.json`
    );
    res.send(JSON.stringify(misp, null, 2));
  });

  app.get('/api/takedown/:domain', (req, res) => {
    const scanId = typeof req.query.scan_id === 'string' ? req.query.scan_id : '';
    const rawChannel =
      typeof req.query.channel === 'string' ? req.query.channel : 'Domain Registrar';
    const channel = ALLOWED_CHANNELS.has(rawChannel) ? rawChannel : 'Domain Registrar';
    const domain = req.params.domain;

    if (!UUID_RE.test(scanId)) {
      res.status(400).json({ detail: 'Invalid scan_id' });
      return;
    }
    const job = scanJobs.get(scanId);
    if (!job || !job.results) {
      res.status(404).json({ detail: 'Scan not found' });
      return;
    }
    const match = job.results.findings.find(
      (f) => f.candidate.domain === domain || f.candidate.ascii_form === domain
    );
    if (!match) {
      res.status(404).json({ detail: 'Domain not found in current scan' });
      return;
    }
    if (!match.facts || !match.facts.is_live) {
      res.json({ error: 'No active hosting observed. Takedown not applicable.' });
      return;
    }
    res.json({
      report: generateTakedownReport(match, channel),
      misp: generateMispEvent(match),
    });
  });

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    if (fs.existsSync(distDir)) {
      app.use(express.static(distDir));
      app.use((_req, res) => {
        res.sendFile(path.join(distDir, 'index.html'));
      });
    }
  }

  const port = Number(process.env.PORT || 3000);
  app.listen(port, '0.0.0.0', () => {
    console.log(`PROTEUS server listening on http://0.0.0.0:${port}`);
  });
}

void startServer();
