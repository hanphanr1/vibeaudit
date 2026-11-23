export const categories = ['Secrets','Supabase & DB','Auth & API','Injection & XSS','Config & AI Guard'] as const;
export type Category = typeof categories[number];
export const severities = ['critical','high','medium','low'] as const;
export type Severity = typeof severities[number];
export type Grade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
export interface Rule { ruleId: string; title: string; category: Category; severity: Severity; cwe: string; owasp: string; description: string }
export interface Finding extends Omit<Rule, 'description'> {
  id: string;
  file: string;
  line: number;
  snippet: string;
  whyItMatters: string;
  patchDiff: string;
  aiFixPrompt: string;
  testSuggestion: string;
}
export interface Hit { ruleId: string; path: string; line: number; snippet: string; patch: string; test: string }
export interface Coverage { complete: boolean; filesAnalyzed: number; skippedAssets: number; incompleteReasons: string[] }
export interface Audit { score: number; grade: Grade; pillars: Record<Category, number>; counts: Record<Severity, number>; findings: Finding[]; warnings: string[]; filesScanned: number; coverage: Coverage }
export interface ScanOptions { exclude?: readonly string[] }
