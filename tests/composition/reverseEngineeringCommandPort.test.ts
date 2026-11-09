import { createHash } from "node:crypto";
import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { expect, it, vi } from "vitest";

import { ReverseEngineeringService } from "../../src/application/reverse/ReverseEngineeringService.js";
import { createReverseEngineeringCommandPort } from "../../src/composition/reverseEngineering.js";
import { analysisErrorProjectionSchema } from "../../src/contracts/errorSchemas.js";
import { projectAnalysisError } from "../../src/domain/analysisErrorProjection.js";
import { execFileOutput } from "../../src/process/ExecFileOutput.js";
import { createWindowsObjdumpInput } from "../../src/objdump/WindowsObjdumpInput.js";

type ExecFileOutputOptions = NonNullable<Parameters<typeof execFileOutput>[2]>;

it.skipIf(process.platform !== "win32")(
  "rejects changed snapshot bytes and relocation of requested DWARF links",
  async () => {
    const directory = await mkdtemp(join(tmpdir(), "rea-objdump-identity-"));
    const path = join(directory, "원본.bin");
    await writeFile(path, "changed since preflight");
    const input = await createWindowsObjdumpInput(path, ["-f", path], false);
    try {
      await expect(input.prepare("a".repeat(64))).rejects.toMatchObject({
        _tag: "AnalysisArtifactChangedError",
      });
      await expect(
        createWindowsObjdumpInput(path, ["-W", "-WK", path], true),
      ).rejects.toMatchObject({
        _tag: "AnalysisCapabilityUnavailableError",
        remediationAction: expect.stringContaining("follow_debug_links=false"),
      });
    } finally {
      await input.close();
      await expect(access(input.resources[0]!)).rejects.toThrow();
      await rm(directory, { recursive: true, force: true });
    }
  },
);

it.skipIf(process.platform !== "win32")(
  "admits Unicode objdump filenames to an immutable private ASCII snapshot",
  async () => {
    const directory = await mkdtemp(join(tmpdir(), "rea-objdump-한글-"));
    const path = join(directory, "-원본 파일.bin");
    const bytes = Buffer.from([0x7f, 0x45, 0x4c, 0x46]);
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    await writeFile(path, bytes);
    let workingPath = "";
    const run = vi.fn(
      async (
        _command: string,
        args: readonly string[],
        options?: ExecFileOutputOptions,
      ) => {
        expect(args).toEqual(["-f", `./${sha256}.bin`]);
        workingPath = join(String(options?.cwd), `${sha256}.bin`);
        expect((await readFile(workingPath)).equals(bytes)).toBe(true);
        await expect(writeFile(workingPath, "changed")).rejects.toThrow();
        return { stdout: "owned output", stderr: "" };
      },
    );
    const service = new ReverseEngineeringService({
      environment: {},
      commands: createReverseEngineeringCommandPort(
        { REA_OBJDUMP_COMMAND: "C:\\tools\\objdump.exe" },
        "win32",
      ),
      run,
    });
    try {
      const result = await service.inspectWithObjdump({
        path,
        operation: "file_headers",
      });
      expect(result.ok).toBe(true);
      expect(run).toHaveBeenCalledOnce();
      if (result.ok) {
        expect(result.value.subject?.local_path).toBe(path);
        expect(result.value.parameters).toMatchObject({
          path,
          command_input: { path: workingPath, sha256 },
        });
        expect(result.value.normalized_result).toMatchObject({
          artifact_changed: false,
        });
      }
      expect((await readFile(path)).equals(bytes)).toBe(true);
      await expect(access(workingPath)).rejects.toThrow();
    } finally {
      await service.close();
      await rm(directory, { recursive: true, force: true });
    }
  },
);

it.skipIf(process.platform !== "win32")(
  "keeps Unicode Windows directories out of objdump argv while retaining source identity",
  async () => {
    const directory = await mkdtemp(join(tmpdir(), "rea-objdump-한글-"));
    const path = join(directory, "-owned.bin");
    await writeFile(path, Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
    const run = vi.fn(
      async (
        _command: string,
        _args: readonly string[],
        _options?: ExecFileOutputOptions,
      ) => ({ stdout: "owned output", stderr: "" }),
    );
    const service = new ReverseEngineeringService({
      environment: {},
      commands: createReverseEngineeringCommandPort(
        { REA_OBJDUMP_COMMAND: "C:\\tools\\objdump.exe" },
        "win32",
      ),
      run,
    });
    try {
      const result = await service.inspectWithObjdump({
        path,
        operation: "file_headers",
      });
      expect(result.ok).toBe(true);
      expect(run.mock.calls[0]?.[1]).toEqual(["-f", "./-owned.bin"]);
      expect(run.mock.calls[0]?.[2]?.cwd).toBe(directory);
      if (result.ok) {
        expect(result.value.subject?.local_path).toBe(path);
        expect(result.value.parameters).toMatchObject({
          path,
          command_cwd: directory,
          command_arguments: ["-f", "./-owned.bin"],
        });
        expect(result.value.normalized_result).toMatchObject({
          artifact_changed: false,
        });
      }
    } finally {
      await service.close();
      await rm(directory, { recursive: true, force: true });
    }
  },
);

it("uses provider profiles supplied through the application port", async () => {
  const directory = await mkdtemp(join(tmpdir(), "rea-reverse-port-"));
  const path = join(directory, "fixture.bin");
  await writeFile(path, Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
  const run = vi.fn(
    async (
      _command: string,
      _args: readonly string[],
      _options?: ExecFileOutputOptions,
    ) => ({ stdout: "injected", stderr: "" }),
  );
  const service = new ReverseEngineeringService({
    environment: { REA_OBJDUMP_COMMAND: "ambient-objdump" },
    commands: {
      objdump: () => ({
        executable: "injected-objdump",
        arguments: ["--injected", path],
        identity: {
          id: "test.objdump",
          name: "Injected objdump",
          version: null,
        },
        environmentOverrides: { INJECTED_PROFILE: "yes" },
      }),
      rizin: () => ({
        executable: "injected-rizin",
        arguments: ["--injected", path],
        identity: { id: "test.rizin", name: "Injected Rizin", version: null },
      }),
    },
    run,
  });

  try {
    const result = await service.inspectWithObjdump({
      path,
      operation: "file_headers",
    });
    expect(result.ok).toBe(true);
    const call = run.mock.calls[0];
    expect(call?.[0]).toBe("injected-objdump");
    expect(call?.[1]).toEqual(["--injected", path]);
    expect(call?.[2]?.env?.INJECTED_PROFILE).toBe("yes");
    if (result.ok) expect(result.value.provider.id).toBe("test.objdump");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("does not reintroduce ambient variables absent from the captured provider environment", async () => {
  const directory = await mkdtemp(join(tmpdir(), "rea-reverse-env-"));
  const path = join(directory, "fixture.bin");
  const variable = "REA_TEST_LATE_PROVIDER_ENV";
  const previous = process.env[variable];
  await writeFile(path, Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
  process.env[variable] = "late-ambient-value";
  const run = vi.fn(
    async (
      _command: string,
      _args: readonly string[],
      _options?: ExecFileOutputOptions,
    ) => ({ stdout: "captured", stderr: "" }),
  );
  const service = new ReverseEngineeringService({
    environment: { REA_OBJDUMP_COMMAND: "captured-objdump" },
    commands: {
      objdump: () => ({
        executable: "captured-objdump",
        arguments: [path],
        identity: {
          id: "test.objdump",
          name: "Captured objdump",
          version: null,
        },
        environmentOverrides: { PROFILE_VALUE: "explicit" },
      }),
      rizin: () => ({
        executable: "captured-rizin",
        arguments: [path],
        identity: { id: "test.rizin", name: "Captured Rizin", version: null },
      }),
    },
    run,
  });

  try {
    await service.inspectWithObjdump({ path, operation: "file_headers" });
    expect(run.mock.calls[0]?.[2]?.env).toEqual({
      REA_OBJDUMP_COMMAND: "captured-objdump",
      PROFILE_VALUE: "explicit",
    });
  } finally {
    if (previous === undefined) delete process.env[variable];
    else process.env[variable] = previous;
    await rm(directory, { recursive: true, force: true });
  }
});

it("projects missing and non-file objdump targets with actionable path reasons", async () => {
  const directory = await mkdtemp(
    join(tmpdir(), "rea-reverse-invalid-target-"),
  );
  const missing = join(directory, "missing.bin");
  const run = vi.fn(async () => ({ stdout: "", stderr: "" }));
  const service = new ReverseEngineeringService({
    commands: {
      objdump: () => ({
        executable: "unused-objdump",
        arguments: [missing],
        identity: {
          id: "test.objdump",
          name: "Test objdump",
          version: null,
        },
      }),
      rizin: ({ path }) => ({
        executable: "unused-rizin",
        arguments: [path],
        identity: { id: "test.rizin", name: "Test Rizin", version: null },
      }),
    },
    run,
  });

  try {
    for (const [path, reason] of [
      [missing, "not found"],
      [directory, "not a regular file"],
    ] as const) {
      const result = await service.inspectWithObjdump({
        path,
        operation: "symbols",
      });
      if (result.ok) throw new Error("Expected target validation failure");
      const projection = projectAnalysisError(result.error);
      expect(analysisErrorProjectionSchema.safeParse(projection).success).toBe(
        true,
      );
      expect(projection).toMatchObject({
        code: "invalid_request",
        category: "invalid_input",
        retryable: false,
        message: expect.stringContaining(path),
        remediation: {
          action: expect.stringContaining("Correct the listed fields"),
        },
        details: {
          operation: "inspect_with_objdump",
          issues: [
            {
              path: ["path"],
              reason: "invalid_value",
              message: expect.stringContaining(reason),
            },
          ],
        },
      });
    }
    expect(run).not.toHaveBeenCalled();
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("keeps target preflight I/O failures out of invalid-input classification", async () => {
  const directory = await mkdtemp(
    join(tmpdir(), "rea-reverse-target-io-failure-"),
  );
  const path = join(directory, "fixture.bin");
  await writeFile(path, Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
  const ioFailure = Object.assign(new Error("device I/O failure"), {
    code: "EIO",
  });
  const stat = vi.fn(async () => {
    throw ioFailure;
  });
  const run = vi.fn(async () => ({ stdout: "", stderr: "" }));
  const service = new ReverseEngineeringService({
    stat,
    commands: {
      objdump: () => ({
        executable: "unused-objdump",
        arguments: [path],
        identity: {
          id: "test.objdump",
          name: "Test objdump",
          version: null,
        },
      }),
      rizin: () => ({
        executable: "unused-rizin",
        arguments: [path],
        identity: { id: "test.rizin", name: "Test Rizin", version: null },
      }),
    },
    run,
  });

  try {
    const result = await service.inspectWithObjdump({
      path,
      operation: "symbols",
    });
    if (result.ok) throw new Error("Expected target preflight I/O failure");
    expect(result.error).toMatchObject({
      _tag: "ProviderAdapterError",
      cause: ioFailure,
      diagnostics: { phase: "target_preflight", system_code: "EIO" },
    });
    expect(projectAnalysisError(result.error)).toMatchObject({
      code: "execution_failure",
      category: "execution_failure",
      retryable: false,
      details: {
        provider_id: "test.objdump",
        operation: "inspect_with_objdump",
        diagnostics: { phase: "target_preflight", system_code: "EIO" },
      },
    });
    expect(run).not.toHaveBeenCalled();
    expect(stat).toHaveBeenCalledOnce();
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it.each([
  { code: "ELOOP", reason: "symbolic-link loop" },
  { code: "ENAMETOOLONG", reason: "path is too long" },
])(
  "classifies selected target $code as correctable input",
  async ({ code, reason }) => {
    const directory = await mkdtemp(
      join(tmpdir(), "rea-reverse-target-path-error-"),
    );
    const path = join(directory, "fixture.bin");
    const pathFailure = Object.assign(new Error(`stat failed: ${code}`), {
      code,
    });
    const stat = vi.fn(async () => {
      throw pathFailure;
    });
    const run = vi.fn(async () => ({ stdout: "", stderr: "" }));
    const service = new ReverseEngineeringService({
      stat,
      commands: {
        objdump: () => ({
          executable: "unused-objdump",
          arguments: [path],
          identity: {
            id: "test.objdump",
            name: "Test objdump",
            version: null,
          },
        }),
        rizin: () => ({
          executable: "unused-rizin",
          arguments: [path],
          identity: { id: "test.rizin", name: "Test Rizin", version: null },
        }),
      },
      run,
    });

    try {
      const result = await service.inspectWithObjdump({
        path,
        operation: "symbols",
      });
      if (result.ok) throw new Error(`Expected ${code} target path failure`);
      expect(result.error).toMatchObject({
        _tag: "AnalysisInputError",
        cause: pathFailure,
      });
      expect(projectAnalysisError(result.error)).toMatchObject({
        code: "invalid_request",
        category: "invalid_input",
        retryable: false,
        message: expect.stringContaining(path),
        details: {
          operation: "inspect_with_objdump",
          issues: [
            {
              path: ["path"],
              reason: "invalid_value",
              message: expect.stringContaining(reason),
            },
          ],
        },
      });
      expect(run).not.toHaveBeenCalled();
      expect(stat).toHaveBeenCalledOnce();
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
