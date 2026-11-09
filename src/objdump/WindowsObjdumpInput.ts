import { join } from "node:path";
import type { ReverseEngineeringCommandInput } from "../application/reverse/ReverseEngineeringCommandPort.js";
import {
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
} from "../domain/analysisErrorCore.js";
import { PrivateRuntimeRoot } from "../process/PrivateRuntimeRoot.js";
import {
  RuntimeControlUnavailableError,
  runtimeControlCapabilityError,
} from "../process/RuntimeControlUnavailableError.js";
import { privateWorkspaceFailure } from "../process/privateWorkspaceFailure.js";
import {
  windowsPrivateRuntime,
  WindowsSnapshotCancelledError,
} from "../windows/WindowsPrivateRuntime.js";
import { OBJDUMP_PROVIDER_IDENTITY } from "./ObjdumpProviderIdentity.js";

const OPERATION = "inspect_with_objdump";

/** Windows native admission binds the ASCII operand to immutable copied bytes. */
export const createWindowsObjdumpInput = async (
  sourcePath: string,
  args: readonly string[],
  followDebugLinks: boolean,
): Promise<ReverseEngineeringCommandInput> => {
  if (followDebugLinks)
    throw new AnalysisCapabilityUnavailableError(
      OBJDUMP_PROVIDER_IDENTITY.id,
      OPERATION,
      "A private ASCII snapshot cannot preserve relative DWARF debug-link resolution for a non-ASCII Windows filename.",
      {
        remediationAction:
          "Use follow_debug_links=false to inspect this artifact's own DWARF data, or select an ASCII-named artifact with its debug-link files kept together.",
      },
    );
  let root: PrivateRuntimeRoot;
  try {
    root = await PrivateRuntimeRoot.create({ prefix: "rea-objdump-" });
  } catch (cause) {
    if (cause instanceof RuntimeControlUnavailableError)
      throw runtimeControlCapabilityError(
        OBJDUMP_PROVIDER_IDENTITY.id,
        OPERATION,
        cause,
      );
    throw privateWorkspaceFailure(
      OBJDUMP_PROVIDER_IDENTITY.id,
      OPERATION,
      cause,
      null,
    );
  }
  return {
    resources: [root.path],
    close: () => root.close(),
    prepare: async (sha256, signal) => {
      if (!/^[a-f0-9]{64}$/u.test(sha256))
        throw new TypeError("Objdump input SHA-256 commitment is invalid");
      const name = `${sha256}.bin`;
      const observed = await windowsPrivateRuntime(root.path)
        .snapshot(sourcePath, name, signal)
        .catch((cause: unknown) => {
          if (cause instanceof WindowsSnapshotCancelledError)
            throw new AnalysisCancelledError(OPERATION, {
              cause: cause.reason,
            });
          throw privateWorkspaceFailure(
            OBJDUMP_PROVIDER_IDENTITY.id,
            OPERATION,
            cause,
            root.path,
          );
        });
      if (observed.sha256 !== sha256)
        throw new AnalysisArtifactChangedError(
          OPERATION,
          sourcePath,
          `Objdump input changed before snapshot admission: expected ${sha256}, observed ${observed.sha256}`,
        );
      return {
        arguments: [...args.slice(0, -1), `./${name}`],
        cwd: root.path,
        observation: {
          path: join(root.path, name),
          sha256: observed.sha256,
          admission: { source: observed.source, snapshot: observed.snapshot },
        },
      };
    },
  };
};
