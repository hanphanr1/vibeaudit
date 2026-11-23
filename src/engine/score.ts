import { type Grade, type Finding, type Audit, type Severity } from './types';
const weights: Record<Severity, number> = { critical: 32, high: 16, medium: 7, low: 3 };
export function scoreFindings(findings: readonly Finding[]): Pick<Audit, 'score' | 'grade' | 'pillars' | 'counts'> {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  const pillars = { 'Secrets': 100, 'Supabase & DB': 100, 'Auth & API': 100, 'Injection & XSS': 100, 'Config & AI Guard': 100 };
  let penalty = 0;
  for (const finding of findings) {
    counts[finding.severity]++;
    penalty += weights[finding.severity];
    pillars[finding.category] = Math.max(0, pillars[finding.category] - weights[finding.severity]);
  }
  const score = Math.max(0, 100 - penalty);
  const grade: Grade = score === 100 ? 'A+' : score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';
  return { score, grade, counts, pillars };
}
