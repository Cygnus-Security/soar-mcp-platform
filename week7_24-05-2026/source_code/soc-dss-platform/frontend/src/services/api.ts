import type { AuthStatus, CorrelationJobStatus, DashboardSummary, ImportProgress, ImportResult, Incident, IncidentFeedback, RiskAssessmentResult, RiskModel, SecurityAlert, WhatIfRequest } from '../types';

const API_BASE = import.meta.env.VITE_API_BASE || '/api/v1';
const READ_CHUNK_BYTES = 1024 * 1024;
const UPLOAD_BATCH_CHARS = 512 * 1024;
const STRUCTURED_JSON_SAMPLE_BYTES = 16 * 1024;
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

type ReportRange = {
  from?: string;
  to?: string;
};

let csrfToken: string | null = null;

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const method = (options?.method ?? 'GET').toUpperCase();
  const headers = new Headers(options?.headers);
  if (!SAFE_METHODS.has(method) && csrfToken) {
    headers.set('X-CSRF-Token', csrfToken);
  }

  const response = await fetch(`${API_BASE}${url}`, { ...options, credentials: 'include', headers });
  if (!response.ok) {
    throw new Error(`API request failed: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

function mergeImportResult(total: ImportResult, next: ImportResult) {
  total.totalLines += next.totalLines;
  total.importedAlerts += next.importedAlerts;
  total.skippedLines += next.skippedLines;
}

function storeAuthStatus(status: AuthStatus) {
  csrfToken = status.csrfToken ?? null;
  return status;
}

function reportQuery(range?: ReportRange) {
  if (!range?.from || !range?.to) {
    return '';
  }
  const params = new URLSearchParams({ from: range.from, to: range.to });
  return `?${params.toString()}`;
}

async function importAlertBatch(lines: string[], batchNumber: number): Promise<ImportResult> {
  const form = new FormData();
  const blob = new Blob([lines.join('\n'), '\n'], { type: 'application/x-ndjson' });
  form.append('file', blob, `alerts-part-${batchNumber}.jsonl`);
  return request<ImportResult>('/import/wazuh-alerts', {
    method: 'POST',
    body: form
  });
}

function shouldParseAsStructuredJson(sample: string) {
  const trimmed = sample.trimStart();
  if (trimmed.startsWith('[')) return true;
  return trimmed.startsWith('{') && (/^\{\s*\n/.test(trimmed) || /"hits"\s*:|"alerts"\s*:/.test(trimmed));
}

function extractAlertRecords(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const hits = record.hits as Record<string, unknown> | undefined;
    if (hits && Array.isArray(hits.hits)) return hits.hits;
    if (Array.isArray(record.alerts)) return record.alerts;
    if (Array.isArray(record.data)) return record.data;
    return [record];
  }
  return [];
}

async function importStructuredJsonFile(file: File, onProgress?: (progress: ImportProgress) => void): Promise<ImportResult> {
  const records = extractAlertRecords(JSON.parse(await file.text()));
  const total: ImportResult = { totalLines: 0, importedAlerts: 0, skippedLines: 0 };
  let batchLines: string[] = [];
  let batchChars = 0;
  let batchNumber = 0;
  let processed = 0;

  async function flushBatch() {
    if (batchLines.length === 0) return;
    batchNumber++;
    const result = await importAlertBatch(batchLines, batchNumber);
    mergeImportResult(total, result);
    batchLines = [];
    batchChars = 0;
    onProgress?.({
      bytesRead: Math.round((processed / Math.max(records.length, 1)) * file.size),
      fileSize: file.size,
      totalLines: total.totalLines,
      importedAlerts: total.importedAlerts,
      skippedLines: total.skippedLines
    });
  }

  for (const record of records) {
    const line = JSON.stringify(record);
    batchLines.push(line);
    batchChars += line.length + 1;
    processed++;
    if (batchChars >= UPLOAD_BATCH_CHARS) {
      await flushBatch();
    }
  }

  await flushBatch();
  onProgress?.({
    bytesRead: file.size,
    fileSize: file.size,
    totalLines: total.totalLines,
    importedAlerts: total.importedAlerts,
    skippedLines: total.skippedLines
  });
  return total;
}

export const api = {
  authStatus: () => request<AuthStatus>('/auth/status').then(storeAuthStatus),
  login: (username: string, password: string) => request<AuthStatus>('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  }).then(storeAuthStatus),
  changePassword: (currentPassword: string, newPassword: string) => request<AuthStatus>('/auth/change-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ currentPassword, newPassword })
  }).then(storeAuthStatus),
  logout: async () => {
    const headers = new Headers();
    if (csrfToken) {
      headers.set('X-CSRF-Token', csrfToken);
    }
    const response = await fetch(`${API_BASE}/auth/logout`, { method: 'POST', credentials: 'include', headers });
    csrfToken = null;
    return response;
  },
  summary: () => request<DashboardSummary>('/dashboard/summary'),
  alerts: () => request<SecurityAlert[]>('/alerts'),
  incidents: () => request<Incident[]>('/incidents'),
  incident: (id: number) => request<Incident>(`/incidents/${id}`),
  feedback: (id: number, feedback: IncidentFeedback) => request<Incident>(`/incidents/${id}/feedback`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(feedback)
  }),
  correlate: () => request<CorrelationJobStatus>('/incidents/correlate', { method: 'POST' }),
  correlationStatus: () => request<CorrelationJobStatus>('/incidents/correlation/status'),
  riskModel: () => request<RiskModel>('/risk-model'),
  updateRiskModel: (model: RiskModel) => request<RiskModel>('/risk-model', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(model)
  }),
  whatIf: (input: WhatIfRequest) => request<RiskAssessmentResult>('/risk-model/what-if', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input)
  }),
  importAlerts: async (file: File, onProgress?: (progress: ImportProgress) => void): Promise<ImportResult> => {
    const sample = await file.slice(0, STRUCTURED_JSON_SAMPLE_BYTES).text();
    if (shouldParseAsStructuredJson(sample)) {
      return importStructuredJsonFile(file, onProgress);
    }

    const decoder = new TextDecoder();
    const total: ImportResult = { totalLines: 0, importedAlerts: 0, skippedLines: 0 };
    let carry = '';
    let batchLines: string[] = [];
    let batchChars = 0;
    let batchNumber = 0;

    async function flushBatch() {
      if (batchLines.length === 0) return;
      batchNumber++;
      const result = await importAlertBatch(batchLines, batchNumber);
      mergeImportResult(total, result);
      batchLines = [];
      batchChars = 0;
    }

    for (let offset = 0; offset < file.size; offset += READ_CHUNK_BYTES) {
      const end = Math.min(offset + READ_CHUNK_BYTES, file.size);
      const buffer = await file.slice(offset, end).arrayBuffer();
      const text = decoder.decode(buffer, { stream: end < file.size });
      const lines = (carry + text).split(/\r?\n/);
      carry = lines.pop() ?? '';

      for (const line of lines) {
        if (!line.trim()) continue;
        batchLines.push(line);
        batchChars += line.length + 1;
        if (batchChars >= UPLOAD_BATCH_CHARS) {
          await flushBatch();
        }
      }

      onProgress?.({
        bytesRead: end,
        fileSize: file.size,
        totalLines: total.totalLines,
        importedAlerts: total.importedAlerts,
        skippedLines: total.skippedLines
      });
    }

    const tail = carry + decoder.decode();
    if (tail.trim()) {
      batchLines.push(tail);
    }
    await flushBatch();

    onProgress?.({
      bytesRead: file.size,
      fileSize: file.size,
      totalLines: total.totalLines,
      importedAlerts: total.importedAlerts,
      skippedLines: total.skippedLines
    });

    return total;
  },
  reportUrl: (range?: ReportRange) => `${API_BASE}/reports/incidents.csv${reportQuery(range)}`,
  reportPdfUrl: (range?: ReportRange) => `${API_BASE}/reports/incidents.pdf${reportQuery(range)}`
};
