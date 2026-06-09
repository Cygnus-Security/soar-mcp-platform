export type RiskLevel = 'Low' | 'Medium' | 'High' | 'Critical';

export interface DashboardSummary {
  totalAlerts: number;
  totalIncidents: number;
  criticalIncidents: number;
  highIncidents: number;
  alertReductionRate: number;
  incidentsByRiskLevel: Record<string, number>;
}

export interface SecurityAlert {
  id: number;
  eventTimestamp: string;
  source: string;
  wazuhRuleId: string;
  wazuhRuleLevel: number;
  agentName: string;
  agentIp?: string;
  sourceIp: string;
  description: string;
  mitreTactic?: string;
  mitreTechnique?: string;
  incidentType: string;
}

export interface Incident {
  id: number;
  title: string;
  incidentType: string;
  riskScore: number;
  riskLevel: RiskLevel;
  status: string;
  sourceIp: string;
  targetAsset: string;
  alertCount: number;
  maxRuleLevel: number;
  firstSeen: string;
  lastSeen: string;
  mitreTactic?: string;
  mitreTechnique?: string;
  recommendation: string;
  explanation: string;
  analystVerdict?: string;
  analystNotes?: string;
  decisionStatus?: string;
  decisionAdvice?: DecisionAdvice;
  riskFactors?: RiskFactor[];
  relatedAlerts: SecurityAlert[];
}

export interface ImportResult {
  totalLines: number;
  importedAlerts: number;
  skippedLines: number;
}

export interface ImportProgress {
  bytesRead: number;
  fileSize: number;
  totalLines: number;
  importedAlerts: number;
  skippedLines: number;
}

export type CorrelationStatusValue = 'IDLE' | 'RUNNING' | 'COMPLETED' | 'FAILED';

export interface CorrelationJobStatus {
  status: CorrelationStatusValue;
  startedAt?: string;
  finishedAt?: string;
  incidentCount?: number;
  message: string;
}

export interface RiskFactor {
  name: string;
  rawScore: number;
  weight: number;
  contribution: number;
  reason: string;
}

export interface RiskAssessmentResult {
  score: number;
  level: RiskLevel;
  explanation: string;
  factors: RiskFactor[];
}

export interface RiskModel {
  severityWeight: number;
  assetWeight: number;
  frequencyWeight: number;
  mitreWeight: number;
  exposureWeight: number;
  vulnerabilityWeight: number;
}

export interface WhatIfRequest {
  assetCriticality: string;
  exposure: string;
  alertCount: number;
  maxRuleLevel: number;
  mitreTactic: string;
  vulnerabilityContext: boolean;
}

export interface IncidentFeedback {
  analystVerdict: string;
  analystNotes: string;
  decisionStatus: string;
}

export interface AuthStatus {
  authenticated: boolean;
  username?: string;
  mustChangePassword: boolean;
  csrfToken?: string;
}

export interface DecisionAdvice {
  priority: string;
  slaHours: number;
  confidence: number;
  escalation: string;
  rationale: string;
  nextActions: string[];
}
