import { createHash } from "node:crypto";
import { access, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect } from "vitest";

import { parseEvidence } from "../../../src/domain/evidence.js";
import { buildManagedPeFixture } from "../../../src/dotnet/ManagedPe.fixture.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest, runFileCli } from "../../support/cli/cliFixture.js";

cliTest(
  "managed output files retain Evidence with a compact exact receipt",
  async ({ cli }) => {
    const cwd = await createTestTempDirectory("rea-managed-output-file-");
    const target = join(cwd, "fixture.dll");
    await writeFile(target, buildManagedPeFixture({ methodRowCount: 2 }));

    for (const command of [
      "inspect-managed-artifact",
      "inspect-managed-members",
      "inspect-managed-native-boundaries",
    ]) {
      const outputPath = join(cwd, command + ".json");
      const invocation = {
        cwd,
        arguments: [command, target, "--output-file", outputPath, "--json"],
      };
      const response = await runFileCli(cli, invocation);
      expect(response.exitCode).toBe(0);
      const bytes = await readFile(outputPath);
      const evidence = parseEvidence(JSON.parse(bytes.toString("utf8")));
      const { coverage } = evidence.normalized_result as {
        coverage: { state: string; issues: unknown[] };
      };
      expect(response.json).toMatchObject({
        path: outputPath,
        bytes: bytes.length,
        sha256: createHash("sha256").update(bytes).digest("hex"),
        evidence_id: evidence.evidence_id,
        coverage: {
          state: coverage.state,
          issue_count: coverage.issues.length,
        },
      });
      expect(response.json).not.toHaveProperty("normalized_result");
      const repeated = await runFileCli(cli, invocation);
      expect(repeated.json).toMatchObject({
        code: "invalid_request",
        details: { reason: "exists" },
      });
      expect((await readFile(outputPath)).equals(bytes)).toBe(true);
    }
  },
);

cliTest(
  "managed output preserves partial coverage and analysis failures",
  async ({ cli }) => {
    const cwd = await createTestTempDirectory("rea-managed-output-coverage-");
    const target = join(cwd, "malformed-il.dll");
    // A volatile. prefix without a following opcode leaves partial CIL coverage.
    await writeFile(
      target,
      buildManagedPeFixture({ ilBody: Buffer.from([10, 0xfe, 0x13]) }),
    );
    const outputPath = join(cwd, "summary.json");
    const bundlePath = join(cwd, "bundle.json");
    const partial = await runFileCli(cli, {
      cwd,
      arguments: [
        "inspect-managed-members",
        target,
        "--detail",
        "summary",
        "--evidence-bundle",
        bundlePath,
        "--output-file",
        outputPath,
        "--json",
      ],
    });
    expect(partial.exitCode).toBe(0);
    expect(partial.json).toMatchObject({ coverage: { state: "partial" } });
    expect(
      parseEvidence(JSON.parse(await readFile(outputPath, "utf8"))).operation,
    ).toBe("inspect_analysis_view");
    await access(bundlePath);

    const missingTarget = join(cwd, "missing.dll");
    const refusedPath = join(cwd, "no-evidence.json");
    const arguments_ = ["inspect-managed-members", missingTarget, "--json"];
    const original = await runFileCli(cli, { cwd, arguments: arguments_ });
    const refused = await runFileCli(cli, {
      cwd,
      arguments: [...arguments_, "--output-file", refusedPath],
    });
    expect(refused.json).toEqual(original.json);
    await expect(access(refusedPath)).rejects.toMatchObject({ code: "ENOENT" });
  },
);
