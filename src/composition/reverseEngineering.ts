import type { ReverseEngineeringServiceRuntimeOptions } from "../application/reverse/ReverseEngineeringService.js";
import type { ReverseEngineeringCommandPort } from "../application/reverse/ReverseEngineeringCommandPort.js";
import { ReverseEngineeringService } from "../application/reverse/ReverseEngineeringService.js";
import { objdumpCommand } from "../objdump/ObjdumpCommand.js";
import { OBJDUMP_PROVIDER_IDENTITY } from "../objdump/ObjdumpProviderIdentity.js";
import {
  rizinCommand,
  rizinCommandLimitations,
} from "../rizin/RizinCommand.js";
import { RIZIN_PROVIDER_IDENTITY } from "../rizin/RizinProviderIdentity.js";
import { resolveWindowsProviderExecutable } from "./resolveWindowsProviderExecutable.js";
import { basename, dirname } from "node:path";
import { absoluteCallerPath } from "../filesystem/callerPath.js";
import { createWindowsObjdumpInput } from "../objdump/WindowsObjdumpInput.js";

export const createReverseEngineeringCommandPort = (
  environment: Readonly<NodeJS.ProcessEnv>,
  platform: NodeJS.Platform = process.platform,
): ReverseEngineeringCommandPort => ({
  objdump: (input) => {
    const args = [...objdumpCommand(input)];
    const path =
      input.operation === "architectures"
        ? undefined
        : absoluteCallerPath(input.path);
    // Windows launches cwd through UTF-16, while GNU objdump builds can decode
    // command-line filenames through a different code page. Retain the original
    // source for admission and Evidence, and avoid encoding its directory in argv.
    const cwd =
      platform === "win32" &&
      path !== undefined &&
      /[^\p{ASCII}]/u.test(dirname(path))
        ? dirname(path)
        : undefined;
    if (cwd !== undefined && path !== undefined)
      args[args.length - 1] = `./${basename(path)}`;
    return {
      executable: providerExecutable(
        environment.REA_OBJDUMP_COMMAND ?? "objdump",
        environment,
        platform,
      ),
      arguments: args,
      ...(cwd === undefined ? {} : { cwd }),
      ...(platform === "win32" &&
      path !== undefined &&
      /[^\p{ASCII}]/u.test(basename(path))
        ? {
            createInput: () =>
              createWindowsObjdumpInput(
                path,
                args,
                input.operation === "dwarf" &&
                  input.follow_debug_links === true,
              ),
          }
        : {}),
      identity: OBJDUMP_PROVIDER_IDENTITY,
      environmentOverrides: { DEBUGINFOD_URLS: "" },
    };
  },
  rizin: (input) => ({
    executable: providerExecutable(
      environment.REA_RIZIN_COMMAND ?? "rizin",
      environment,
      platform,
    ),
    arguments: rizinCommand(input),
    limitations: rizinCommandLimitations(input),
    identity: RIZIN_PROVIDER_IDENTITY,
  }),
});

const providerExecutable = (
  executable: string,
  environment: Readonly<NodeJS.ProcessEnv>,
  platform: NodeJS.Platform,
): string =>
  platform === "win32"
    ? resolveWindowsProviderExecutable(executable, environment)
    : executable;

/** Compose BYO reverse-engineering commands without acquiring tools at import time. */
export const createReverseEngineeringService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
  options: ReverseEngineeringServiceRuntimeOptions = {},
): ReverseEngineeringService => {
  const environmentSnapshot = { ...environment };
  return new ReverseEngineeringService({
    ...options,
    environment: environmentSnapshot,
    commands: createReverseEngineeringCommandPort(environmentSnapshot),
  });
};
