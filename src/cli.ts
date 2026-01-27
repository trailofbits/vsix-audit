import { Command } from "commander";
import pc from "picocolors";
import { downloadExtension } from "./scanner/download.js";
import { scanExtension } from "./scanner/index.js";

export const cli = new Command()
  .name("vsix-audit")
  .description("Security scanner for VS Code extensions")
  .version("0.1.0");

cli
  .command("scan")
  .description("Scan a VS Code extension for security issues")
  .argument("<target>", "Path to .vsix file or extension ID (e.g., publisher.extension)")
  .option("-o, --output <format>", "Output format (text, json, sarif)", "text")
  .option("-s, --severity <level>", "Minimum severity to report (low, medium, high, critical)", "low")
  .option("--no-network", "Disable network-based checks")
  .action(async (target: string, options: ScanOptions) => {
    try {
      const result = await scanExtension(target, options);
      if (options.output === "json") {
        console.log(JSON.stringify(result, null, 2));
      } else if (options.output === "sarif") {
        console.log(JSON.stringify(toSarif(result), null, 2));
      } else {
        printTextReport(result);
      }
      process.exit(result.findings.length > 0 ? 1 : 0);
    } catch (error) {
      console.error(pc.red("Error:"), error instanceof Error ? error.message : error);
      process.exit(2);
    }
  });

cli
  .command("download")
  .description("Download a VS Code extension from the marketplace")
  .argument("<extension-id>", "Extension ID (e.g., ms-python.python or ms-python.python@2024.1.0)")
  .option("-o, --output <dir>", "Output directory", process.cwd())
  .action(async (extensionId: string, options: { output: string }) => {
    try {
      console.log(pc.cyan("Downloading:"), extensionId);

      const result = await downloadExtension(extensionId, { destDir: options.output });

      console.log();
      console.log(pc.green("✓ Downloaded successfully"));
      console.log(pc.dim("─".repeat(50)));
      console.log(`${pc.cyan("Name:")} ${result.metadata.displayName ?? result.metadata.name}`);
      console.log(`${pc.cyan("Publisher:")} ${result.metadata.publisher}`);
      console.log(`${pc.cyan("Version:")} ${result.metadata.version}`);
      if (result.metadata.installCount) {
        console.log(`${pc.cyan("Installs:")} ${result.metadata.installCount.toLocaleString()}`);
      }
      console.log(`${pc.cyan("Path:")} ${result.path}`);
    } catch (error) {
      console.error(pc.red("Error:"), error instanceof Error ? error.message : error);
      process.exit(2);
    }
  });

cli
  .command("info")
  .description("Display metadata about a VS Code extension")
  .argument("<target>", "Path to .vsix file or extension ID")
  .action(async (target: string) => {
    console.log(pc.cyan("Extension info for:"), target);
    console.log(pc.dim("(Not yet implemented)"));
  });

interface ScanOptions {
  output: "text" | "json" | "sarif";
  severity: "low" | "medium" | "high" | "critical";
  network: boolean;
}

interface ScanResult {
  extension: {
    id: string;
    name: string;
    version: string;
    publisher: string;
  };
  findings: Finding[];
  metadata: {
    scannedAt: string;
    scanDuration: number;
  };
}

interface Finding {
  id: string;
  title: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  category: string;
  location?: {
    file: string;
    line?: number;
  };
}

function printTextReport(result: ScanResult): void {
  console.log();
  console.log(pc.bold("vsix-audit scan results"));
  console.log(pc.dim("─".repeat(50)));
  console.log();
  console.log(`${pc.cyan("Extension:")} ${result.extension.name} v${result.extension.version}`);
  console.log(`${pc.cyan("Publisher:")} ${result.extension.publisher}`);
  console.log(`${pc.cyan("Scanned:")} ${result.metadata.scannedAt}`);
  console.log();

  if (result.findings.length === 0) {
    console.log(pc.green("✓ No security issues found"));
    return;
  }

  console.log(pc.yellow(`Found ${result.findings.length} issue(s):`));
  console.log();

  for (const finding of result.findings) {
    const severityColor = {
      critical: pc.red,
      high: pc.red,
      medium: pc.yellow,
      low: pc.blue,
    }[finding.severity];

    console.log(`  ${severityColor(`[${finding.severity.toUpperCase()}]`)} ${finding.title}`);
    console.log(`  ${pc.dim(finding.description)}`);
    if (finding.location) {
      console.log(`  ${pc.dim(`at ${finding.location.file}${finding.location.line ? `:${finding.location.line}` : ""}`)}`);
    }
    console.log();
  }
}

function toSarif(result: ScanResult): object {
  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "vsix-audit",
            version: "0.1.0",
            informationUri: "https://github.com/trailofbits/vsix-audit",
          },
        },
        results: result.findings.map((f) => ({
          ruleId: f.id,
          level: f.severity === "critical" || f.severity === "high" ? "error" : "warning",
          message: { text: f.description },
          locations: f.location
            ? [
                {
                  physicalLocation: {
                    artifactLocation: { uri: f.location.file },
                    region: f.location.line ? { startLine: f.location.line } : undefined,
                  },
                },
              ]
            : [],
        })),
      },
    ],
  };
}
