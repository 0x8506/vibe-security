import { readdir, readFile, stat } from "node:fs/promises";
import { join, extname, relative } from "node:path";
import chalk from "chalk";
import ora from "ora";
import type {
  SecurityIssue,
  ScanResult,
  ScanOptions,
  SecuritySeverity,
} from "../types/index.js";
import { SECURITY_RULES } from "../utils/security-rules.js";
import { logger } from "../utils/logger.js";

const LANGUAGE_EXTENSIONS: Record<string, string[]> = {
  javascript: [".js", ".jsx", ".mjs", ".cjs"],
  typescript: [".ts", ".tsx"],
  python: [".py"],
  java: [".java"],
  csharp: [".cs"],
  php: [".php"],
  ruby: [".rb"],
  go: [".go"],
  rust: [".rs"],
};

const DEFAULT_EXCLUDES = [
  "node_modules",
  ".git",
  "dist",
  "build",
  "coverage",
  ".next",
  ".nuxt",
  "vendor",
  "__pycache__",
  "venv",
  ".venv",
];

export async function scanCommand(options: ScanOptions = {}): Promise<void> {
  const startTime = Date.now();
  const scanPath = options.path || process.cwd();

  logger.title("Vibe Security Scanner");
  logger.info(`Scanning: ${chalk.cyan(scanPath)}`);

  const spinner = ora("Scanning files...").start();

  try {
    const issues: SecurityIssue[] = [];
    const filesScanned = await scanDirectory(
      scanPath,
      issues,
      options.exclude || DEFAULT_EXCLUDES
    );

    const duration = Date.now() - startTime;

    // Count by severity
    const severityCounts = {
      critical: issues.filter((i) => i.severity === "critical").length,
      high: issues.filter((i) => i.severity === "high").length,
      medium: issues.filter((i) => i.severity === "medium").length,
      low: issues.filter((i) => i.severity === "low").length,
      info: issues.filter((i) => i.severity === "info").length,
    };

    const result: ScanResult = {
      totalIssues: issues.length,
      ...severityCounts,
      issues,
      filesScanned,
      duration,
    };

    spinner.succeed(`Scanned ${filesScanned} files in ${duration}ms`);

    // Display results
    displayResults(result, options);

    // Auto-fix if requested
    if (options.fix && issues.length > 0) {
      await autoFixIssues(issues);
    }
  } catch (error) {
    spinner.fail("Scan failed");
    if (error instanceof Error) {
      logger.error(error.message);
    }
    process.exit(1);
  }
}

async function scanDirectory(
  dirPath: string,
  issues: SecurityIssue[],
  excludes: string[]
): Promise<number> {
  let filesScanned = 0;

  try {
    const entries = await readdir(dirPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = join(dirPath, entry.name);

      // Skip excluded directories/files
      if (excludes.some((exclude) => entry.name.includes(exclude))) {
        continue;
      }

      if (entry.isDirectory()) {
        filesScanned += await scanDirectory(fullPath, issues, excludes);
      } else if (entry.isFile()) {
        const language = getLanguageFromExtension(extname(entry.name));
        if (language) {
          await scanFile(fullPath, language, issues);
          filesScanned++;
        }
      }
    }
  } catch (error) {
    // Skip files/directories we can't access
  }

  return filesScanned;
}

async function scanFile(
  filePath: string,
  language: string,
  issues: SecurityIssue[]
): Promise<void> {
  try {
    const content = await readFile(filePath, "utf-8");
    const lines = content.split("\n");

    // Get applicable rules for this language
    const rules = SECURITY_RULES.filter((rule) =>
      rule.languages.includes(language)
    );

    for (const rule of rules) {
      const pattern =
        typeof rule.pattern === "string"
          ? new RegExp(rule.pattern, "gi")
          : rule.pattern;

      let match;
      const regex = new RegExp(pattern);

      // Find all matches in the file
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        regex.lastIndex = 0;

        while ((match = regex.exec(line)) !== null) {
          issues.push({
            id: rule.id,
            file: filePath,
            line: i + 1,
            column: match.index,
            severity: rule.severity,
            category: rule.category,
            title: rule.name,
            description: rule.description,
            code: line.trim(),
            cwe: rule.cwe,
            owasp: rule.owasp,
          });
        }
      }
    }
  } catch (error) {
    // Skip files we can't read
  }
}

function getLanguageFromExtension(ext: string): string | null {
  for (const [language, extensions] of Object.entries(LANGUAGE_EXTENSIONS)) {
    if (extensions.includes(ext.toLowerCase())) {
      return language;
    }
  }
  return null;
}

function displayResults(result: ScanResult, options: ScanOptions): void {
  console.log();

  if (result.totalIssues === 0) {
    logger.success("No security issues found! 🎉");
    return;
  }

  // Summary
  console.log(chalk.bold("Security Issues Found:"));
  console.log();

  if (result.critical > 0) {
    console.log(`  ${chalk.bgRed.white.bold(" CRITICAL ")} ${result.critical}`);
  }
  if (result.high > 0) {
    console.log(`  ${chalk.red.bold("HIGH")}      ${result.high}`);
  }
  if (result.medium > 0) {
    console.log(`  ${chalk.yellow.bold("MEDIUM")}    ${result.medium}`);
  }
  if (result.low > 0) {
    console.log(`  ${chalk.blue.bold("LOW")}       ${result.low}`);
  }
  if (result.info > 0) {
    console.log(`  ${chalk.gray.bold("INFO")}      ${result.info}`);
  }

  console.log();
  console.log(chalk.dim("─".repeat(80)));

  // Group issues by file
  const issuesByFile = new Map<string, SecurityIssue[]>();
  for (const issue of result.issues) {
    if (!issuesByFile.has(issue.file)) {
      issuesByFile.set(issue.file, []);
    }
    issuesByFile.get(issue.file)!.push(issue);
  }

  // Display issues
  let displayedCount = 0;
  const maxDisplay = 50; // Limit display to avoid overwhelming output

  for (const [file, fileIssues] of issuesByFile) {
    if (displayedCount >= maxDisplay) {
      console.log(
        chalk.dim(
          `\n... and ${result.totalIssues - displayedCount} more issues`
        )
      );
      break;
    }

    console.log();
    console.log(chalk.bold(relative(process.cwd(), file)));

    for (const issue of fileIssues) {
      if (displayedCount >= maxDisplay) break;

      const severityColor = getSeverityColor(issue.severity);
      const severityBadge = chalk[severityColor](
        issue.severity.toUpperCase().padEnd(8)
      );

      console.log(`  ${severityBadge} Line ${issue.line}`);
      console.log(`  ${chalk.dim("│")} ${issue.title}`);
      console.log(`  ${chalk.dim("│")} ${chalk.dim(issue.description)}`);

      if (issue.code) {
        console.log(`  ${chalk.dim("│")} ${chalk.gray(issue.code)}`);
      }

      if (issue.cwe || issue.owasp) {
        const refs = [];
        if (issue.cwe) refs.push(chalk.dim(issue.cwe));
        if (issue.owasp) refs.push(chalk.dim(issue.owasp));
        console.log(`  ${chalk.dim("└")} ${refs.join(" • ")}`);
      }

      console.log();
      displayedCount++;
    }
  }

  // Output format options
  if (options.format === "json") {
    console.log(JSON.stringify(result, null, 2));
  }
}

function getSeverityColor(
  severity: SecuritySeverity
): "red" | "yellow" | "blue" | "gray" {
  switch (severity) {
    case "critical":
    case "high":
      return "red";
    case "medium":
      return "yellow";
    case "low":
      return "blue";
    case "info":
      return "gray";
    default:
      return "gray";
  }
}

async function autoFixIssues(issues: SecurityIssue[]): Promise<void> {
  console.log();
  logger.info("Auto-fixing issues...");

  const spinner = ora("Applying fixes...").start();

  let fixedCount = 0;

  // Group by file
  const issuesByFile = new Map<string, SecurityIssue[]>();
  for (const issue of issues) {
    if (!issuesByFile.has(issue.file)) {
      issuesByFile.set(issue.file, []);
    }
    issuesByFile.get(issue.file)!.push(issue);
  }

  // Apply fixes (placeholder - would need actual fix implementation)
  spinner.text = `Fixed ${fixedCount} issues`;

  spinner.succeed(`Auto-fixed ${fixedCount} issues`);

  if (fixedCount < issues.length) {
    logger.warn(`${issues.length - fixedCount} issues require manual review`);
  }
}
