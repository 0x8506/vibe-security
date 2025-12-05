export type AIType =
  | "claude"
  | "cursor"
  | "windsurf"
  | "antigravity"
  | "copilot"
  | "all";

export interface Release {
  tag_name: string;
  name: string;
  published_at: string;
  html_url: string;
  assets: Asset[];
}

export interface Asset {
  name: string;
  browser_download_url: string;
  size: number;
}

export interface InstallConfig {
  aiType: AIType;
  version?: string;
  force?: boolean;
}

export const AI_TYPES: AIType[] = [
  "claude",
  "cursor",
  "windsurf",
  "antigravity",
  "copilot",
  "all",
];

export const AI_FOLDERS: Record<Exclude<AIType, "all">, string[]> = {
  claude: [".claude"],
  cursor: [".cursor"],
  windsurf: [".windsurf"],
  antigravity: [".agent"],
  copilot: [".github"],
};

// Security types
export type SecuritySeverity = "critical" | "high" | "medium" | "low" | "info";

export interface SecurityIssue {
  id: string;
  file: string;
  line: number;
  column?: number;
  severity: SecuritySeverity;
  category: string;
  title: string;
  description: string;
  code?: string;
  fix?: string;
  cwe?: string;
  owasp?: string;
}

export interface ScanResult {
  totalIssues: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  issues: SecurityIssue[];
  filesScanned: number;
  duration: number;
}

export interface SecurityRule {
  id: string;
  name: string;
  severity: SecuritySeverity;
  category: string;
  description: string;
  pattern: RegExp | string;
  languages: string[];
  cwe?: string;
  owasp?: string;
  autoFix?: (code: string, match: RegExpMatchArray) => string;
}

export interface ScanOptions {
  path?: string;
  fix?: boolean;
  severity?: SecuritySeverity[];
  category?: string[];
  exclude?: string[];
  format?: "text" | "json" | "sarif";
}
