import type { EvidenceProvider } from "../../domain/evidence.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import type {
  ObjdumpSelection,
  RizinInput,
} from "../../domain/reverseEngineering.js";

/** One private input owner; the workflow retains it until its child is stopped. */
export interface ReverseEngineeringCommandInput {
  readonly resources: readonly string[];
  prepare(
    sha256: string,
    signal?: AbortSignal,
  ): Promise<{
    readonly arguments: readonly string[];
    readonly cwd: string;
    readonly observation: JsonValue;
  }>;
  close(): Promise<void>;
}

/** Provider-neutral command profile consumed by the shared application workflow. */
export interface ReverseEngineeringProviderCommand {
  readonly executable: string;
  readonly arguments: readonly string[];
  /** Owned subprocess working directory, when argument spelling depends on it. */
  readonly cwd?: string;
  readonly createInput?: () => Promise<ReverseEngineeringCommandInput>;
  readonly identity: EvidenceProvider;
  /** What the provider cannot attest about the arguments it built. */
  readonly limitations?: readonly string[];
  readonly environmentOverrides?: Readonly<NodeJS.ProcessEnv>;
}

/** Provider-specific command construction stays outside the application layer. */
export interface ReverseEngineeringCommandPort {
  objdump(input: ObjdumpSelection): ReverseEngineeringProviderCommand;
  rizin(input: RizinInput): ReverseEngineeringProviderCommand;
}
