import { createHash } from "node:crypto";
import {
  isObject,
  projectCliAnalysisResult,
} from "./projectCliAnalysisResult.js";
import { z } from "incur";

import { compareManagedMemberPaths } from "../application/managed/ManagedMemberComparisonService.js";
import { executeManagedNativeBoundaries } from "../application/managed/ManagedNativeVerificationService.js";
import { importManagedReconstructionEvidence } from "../application/managed/ManagedReconstructionService.js";
import type { DirectAnalysis } from "../composition/directAnalysis.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { parseCliJsonInput } from "../cliJsonInput.js";
import { MANAGED_STATIC_PROVIDER } from "../domain/investigationProviders.js";
import { ok } from "../domain/result.js";
import {
  evidenceBundleOption,
  runEvidenceInputCommand,
} from "./evidenceInputCommand.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { registerProjectManagedApplicationGraph } from "./managedProjectGraphCommand.js";
import { managedMembersInputSchema } from "../contracts/managed/managedToolContracts.js";
import {
  absoluteLocalPathStringSchema,
  localPathStringSchema,
} from "../domain/localPath.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import { writeTextParts } from "../application/JsonFiles.js";
import { bufferedJsonParts } from "../domain/jsonSerialization.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { Evidence } from "../domain/evidence.js";
import type { JsonValue } from "../domain/jsonValue.js";
import type { Result } from "../domain/result.js";
import { jsonOutputParts } from "./jsonOutput.js";

const managedOutputFileOption = absoluteLocalPathStringSchema
  .optional()
  .describe(
    "Write this command's Evidence JSON to a new absolute file and return a compact receipt; never replaces an existing path",
  );

const deliverManagedOutput = async (
  result: Result<Evidence, JsonValue>,
  outputPath: string | undefined,
  signal: AbortSignal,
) => {
  if (!result.ok || outputPath === undefined)
    return projectCliAnalysisResult(result);

  const evidence = result.value;
  const hash = createHash("sha256");
  function* outputParts() {
    for (const part of bufferedJsonParts(
      jsonOutputParts(evidence, "json", false),
    )) {
      hash.update(part);
      yield part;
    }
  }
  const resources = new ArtifactResourceScope();
  const written = await writeTextParts(
    outputParts(),
    outputPath,
    false,
    resources,
    {
      signal,
      operation: evidence.operation,
    },
  );
  if (!written.ok) {
    await resources.close().catch(() => undefined);
    return {
      error: "Managed Evidence output failed",
      ...projectAnalysisError(written.error, "invocation"),
    };
  }

  const normalized = evidence.normalized_result;
  const coverageOwner =
    isObject(normalized) &&
    normalized.kind === "summary" &&
    normalized.parent_operation === "inspect_managed_members"
      ? normalized.summary
      : normalized;
  const coverage = isObject(coverageOwner) ? coverageOwner.coverage : undefined;
  return {
    kind: "managed-evidence-file",
    ...written.value,
    sha256: hash.digest("hex"),
    evidence_id: evidence.evidence_id,
    operation: evidence.operation,
    coverage: isObject(coverage)
      ? {
          state: coverage.state ?? null,
          issue_count: Array.isArray(coverage.issues)
            ? coverage.issues.length
            : null,
        }
      : { state: null, issue_count: null },
  };
};

export const registerManagedCommands = (
  cli: CliInstance,
  logger: Logger,
  runProviderAnalysis: DirectAnalysis["runProviderAnalysis"],
): void => {
  registerInspectManagedArtifact(cli, logger, runProviderAnalysis);
  registerInspectManagedMembers(cli, logger, runProviderAnalysis);
  registerInspectManagedNativeBoundaries(cli, logger, runProviderAnalysis);
  registerCompareManagedMembers(cli, logger);
  registerImportManagedReconstruction(cli, logger);
  registerVerifyManagedNativeBoundaries(cli, logger);
  registerProjectManagedApplicationGraph(cli, logger);
};

const registerInspectManagedArtifact = (
  cli: CliInstance,
  logger: Logger,
  runProviderAnalysis: DirectAnalysis["runProviderAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.inspectManagedArtifact, {
    description: "Inspect PE/CLI identity without loading target code",
    args: z.object({
      path: localPathStringSchema.describe(
        "Managed PE executable or assembly path",
      ),
    }),
    options: z.object({ outputFile: managedOutputFileOption }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, "inspect-managed-artifact", () =>
          runProviderAnalysis(
            args.path,
            "inspect_managed_artifact",
            {},
            logger,
            signal,
          ).then((result) =>
            deliverManagedOutput(result, options.outputFile, signal),
          ),
        ),
      ),
  });
};

const registerInspectManagedMembers = (
  cli: CliInstance,
  logger: Logger,
  runProviderAnalysis: DirectAnalysis["runProviderAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.inspectManagedMembers, {
    description:
      "Inspect PE/CLI metadata members, signatures, CIL anchors, and ldstr string literals without loading target code",
    args: z.object({
      path: localPathStringSchema.describe(
        "Managed PE executable or assembly path",
      ),
    }),
    options: z.object({
      outputFile: managedOutputFileOption,
      type: managedMembersInputSchema.shape.type_names.describe(
        "Inspect only members declared by this exact type full name, and the string literals they load, such as System.Threading.Monitor; a nested type is named by its bare name, which selects every nested type of that name (repeatable)",
      ),
      detail: managedMembersInputSchema.shape.detail.describe(
        "complete returns full Evidence (default); summary returns identity, selection, coverage, limitations and collection counts and requires --evidence-bundle",
      ),
      evidenceBundle: localPathStringSchema
        .optional()
        .describe(
          "Write complete parent Evidence to a new local bundle for later inspect-analysis-view calls; never replaces an existing path",
        ),
    }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, "inspect-managed-members", () =>
          runProviderAnalysis(
            args.path,
            "inspect_managed_members",
            options.type === undefined ? {} : { type_names: options.type },
            logger,
            signal,
            {
              ...(options.detail === undefined
                ? {}
                : { detail: options.detail }),
              ...(options.evidenceBundle === undefined
                ? {}
                : { evidenceBundlePath: options.evidenceBundle }),
            },
          ).then((result) =>
            deliverManagedOutput(result, options.outputFile, signal),
          ),
        ),
      ),
  });
};

const registerInspectManagedNativeBoundaries = (
  cli: CliInstance,
  logger: Logger,
  runProviderAnalysis: DirectAnalysis["runProviderAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.inspectManagedNativeBoundaries, {
    description:
      "Inspect PE/CLI PInvoke and native implementation boundary declarations without loading target code",
    args: z.object({
      path: localPathStringSchema.describe(
        "Managed PE executable or assembly path",
      ),
    }),
    options: z.object({ outputFile: managedOutputFileOption }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, "inspect-managed-native-boundaries", () =>
          runProviderAnalysis(
            args.path,
            "inspect_managed_native_boundaries",
            {},
            logger,
            signal,
          ).then((result) =>
            deliverManagedOutput(result, options.outputFile, signal),
          ),
        ),
      ),
  });
};

const compareManagedMemberArgs = z.object({
  leftPath: localPathStringSchema.describe(
    "Baseline managed PE executable or assembly",
  ),
  rightPath: localPathStringSchema.describe(
    "Candidate managed PE executable or assembly",
  ),
});

const registerCompareManagedMembers = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.compareManagedMembers, {
    description:
      "Compare managed PE/CLI member inventories by exact declared type, name, and signature; names alone never form a match",
    args: compareManagedMemberArgs,
    options: z.object({
      type: managedMembersInputSchema.shape.type_names.describe(
        "Compare only members declared by this exact type full name on both sides, as selected by inspect-managed-members --type; use it when a whole-assembly comparison exceeds capacity (repeatable)",
      ),
    }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, "compare-managed-members", async () => {
          const resources = new ArtifactResourceScope();
          const result = await finishAnalysisCommand(
            () =>
              compareManagedMemberPaths(
                {
                  leftPath: args.leftPath,
                  rightPath: args.rightPath,
                  ...(options.type === undefined
                    ? {}
                    : { typeNames: options.type }),
                },
                {},
                resources,
              ),
            resources,
            MANAGED_STATIC_PROVIDER.id,
            "compare_managed_members",
            signal,
            "Managed member comparison resources",
          );
          return result.ok
            ? result.value
            : { error: "Managed member comparison failed", ...result.error };
        }),
      ),
  });
};

const registerImportManagedReconstruction = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.importManagedReconstruction, {
    description:
      "Import decompiler-produced managed reconstruction against exact static member evidence",
    args: z.object({
      inputJson: z
        .string()
        .describe("Inline managed reconstruction JSON or JSON file path"),
    }),
    options: z.object({ evidenceBundle: evidenceBundleOption }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, "import-managed-reconstruction", async () => {
          const input = await parseCliJsonInput(
            args.inputJson,
            "import-managed-reconstruction",
            signal,
          );
          if (!input.ok) return input.error;
          return runEvidenceInputCommand(
            "import_managed_reconstruction",
            options.evidenceBundle,
            signal,
            (lookup) =>
              Promise.resolve(
                importManagedReconstructionEvidence(input.value, lookup, {
                  signal,
                }),
              ),
          ).then(projectCliAnalysisResult);
        }),
      ),
  });
};

const registerVerifyManagedNativeBoundaries = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.verifyManagedNativeBoundaries, {
    description:
      "Verify managed P/Invoke declarations against authenticated native Evidence",
    args: z.object({
      inputJson: z
        .string()
        .describe("Inline managed/native verification JSON or JSON file path"),
    }),
    options: z.object({ evidenceBundle: evidenceBundleOption }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, "verify-managed-native-boundaries", async () => {
          const input = await parseCliJsonInput(
            args.inputJson,
            "verify-managed-native-boundaries",
            signal,
          );
          if (!input.ok) return input.error;
          return runEvidenceInputCommand(
            "verify_managed_native_boundaries",
            options.evidenceBundle,
            signal,
            (lookup) => {
              const result = executeManagedNativeBoundaries(
                input.value,
                lookup,
                { signal },
              );
              return Promise.resolve(
                result.ok ? ok(result.value.evidence) : result,
              );
            },
          ).then(projectCliAnalysisResult);
        }),
      ),
  });
};
