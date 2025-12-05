#!/usr/bin/env node

import { Command } from "commander";
import { initCommand } from "./commands/init.js";
import { versionsCommand } from "./commands/versions.js";
import { updateCommand } from "./commands/update.js";
import { scanCommand } from "./commands/scan.js";
import { verifyCommand } from "./commands/verify.js";
import type { AIType } from "./types/index.js";
import { AI_TYPES } from "./types/index.js";

const program = new Command();

program
  .name("vibesec")
  .description(
    "Vibe Security - Find, verify and fix security vulnerabilities in your code"
  )
  .version("1.0.2");

// Security commands
program
  .command("scan")
  .description("Scan code for security vulnerabilities")
  .option("-p, --path <path>", "Path to scan (default: current directory)")
  .option("-f, --fix", "Automatically fix issues where possible")
  .option(
    "-s, --severity <levels...>",
    "Filter by severity: critical, high, medium, low"
  )
  .option("-c, --category <categories...>", "Filter by category")
  .option("-e, --exclude <patterns...>", "Exclude files/directories")
  .option("--format <format>", "Output format: text, json, sarif", "text")
  .action(async (options) => {
    await scanCommand({
      path: options.path,
      fix: options.fix,
      severity: options.severity,
      category: options.category,
      exclude: options.exclude,
      format: options.format,
    });
  });

program
  .command("verify")
  .description("Verify security posture of your codebase")
  .option("-p, --path <path>", "Path to verify (default: current directory)")
  .option("--strict", "Fail on any security issues")
  .option(
    "--threshold <level>",
    "Severity threshold: critical, high, medium, low",
    "high"
  )
  .action(async (options) => {
    await verifyCommand({
      path: options.path,
      strict: options.strict,
      threshold: options.threshold,
    });
  });

// Original Vibe Security commands (kept for compatibility)
program
  .command("init")
  .description("Install security rules for AI coding assistant")
  .option("-a, --ai <type>", `AI assistant type (${AI_TYPES.join(", ")})`)
  .option("-f, --force", "Overwrite existing files")
  .option("-v, --version <tag>", "Install specific version (e.g., v1.0.0)")
  .action(async (options) => {
    if (options.ai && !AI_TYPES.includes(options.ai)) {
      console.error(`Invalid AI type: ${options.ai}`);
      console.error(`Valid types: ${AI_TYPES.join(", ")}`);
      process.exit(1);
    }
    await initCommand({
      ai: options.ai as AIType | undefined,
      force: options.force,
      version: options.version,
    });
  });

program
  .command("versions")
  .description("List available versions")
  .action(versionsCommand);

program
  .command("update")
  .description("Update security rules to latest version")
  .option("-a, --ai <type>", `AI assistant type (${AI_TYPES.join(", ")})`)
  .action(async (options) => {
    if (options.ai && !AI_TYPES.includes(options.ai)) {
      console.error(`Invalid AI type: ${options.ai}`);
      console.error(`Valid types: ${AI_TYPES.join(", ")}`);
      process.exit(1);
    }
    await updateCommand({
      ai: options.ai as AIType | undefined,
    });
  });

program.parse();
