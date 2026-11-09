import { expect, it, vi } from "vitest";
import { ReverseEngineeringService } from "../../src/application/reverse/ReverseEngineeringService.js";
import type {
  ReverseEngineeringCommandInput,
  ReverseEngineeringProviderCommand,
} from "../../src/application/reverse/ReverseEngineeringCommandPort.js";
import { OwnedCommandFailure } from "../../src/process/OwnedCommand.js";
import type { ProviderProcessSupervisor } from "../../src/process/ProviderProcess.js";
import { providerSnapshot } from "../support/reverseEngineeringCompositionFixtures.js";

const sha256 = "a".repeat(64);
const deferred = () => {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
};
const inputOwner = (): ReverseEngineeringCommandInput => ({
  resources: ["owned-input-root"],
  prepare: async () => ({
    arguments: ["./input.bin"],
    cwd: "owned-input-root",
    observation: { path: "owned-input-root/input.bin", sha256 },
  }),
  close: vi.fn(async () => {}),
});
const commands = (input: ReverseEngineeringCommandInput) => {
  const profile: ReverseEngineeringProviderCommand = {
    executable: "test-command",
    arguments: ["original"],
    identity: { id: "test", name: "Test", version: null },
  };
  return {
    objdump: () => ({ ...profile, createInput: async () => input }),
    rizin: () => profile,
  };
};

it("retains the completed observation when cancellation arrives during final input cleanup", async () => {
  const input = inputOwner();
  const closing = deferred();
  const released = deferred();
  input.close = async () => {
    closing.resolve();
    await released.promise;
  };
  const controller = new AbortController();
  const service = new ReverseEngineeringService({
    commands: commands(input),
    digest: async () => sha256,
    run: async () => ({ stdout: "completed before cancellation", stderr: "" }),
  });
  const pending = service.inspectWithObjdump(
    { path: "original", operation: "file_headers" },
    { signal: controller.signal },
  );
  await closing.promise;
  controller.abort("finalization cancellation");
  released.resolve();
  try {
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok)
      expect(result.error).toMatchObject({
        _tag: "AnalysisCancelledError",
        cause: "finalization cancellation",
        partialObservation: {
          normalized_result: { stdout: "completed before cancellation" },
        },
      });
  } finally {
    released.resolve();
    await service.close();
  }
});

it("keeps an active input lease while another command retries cleanup", async () => {
  const input = inputOwner();
  const entered = deferred();
  const release = deferred();
  const service = new ReverseEngineeringService({
    commands: commands(input),
    digest: async () => sha256,
    run: async (_command, args) => {
      if (args[0] === "./input.bin") {
        entered.resolve();
        await release.promise;
      }
      return { stdout: "observed", stderr: "" };
    },
  });
  const running = service.inspectWithObjdump({
    path: "original",
    operation: "file_headers",
  });
  try {
    await entered.promise;
    expect(
      (await service.executeRizinCommand({ path: "other", command: "i" })).ok,
    ).toBe(true);
    expect(input.close).not.toHaveBeenCalled();
    release.resolve();
    expect((await running).ok).toBe(true);
    expect(input.close).toHaveBeenCalledOnce();
  } finally {
    release.resolve();
    await running;
    await service.close();
  }
});

it("retains failed input cleanup and resolves its original error on retry", async () => {
  const input = inputOwner();
  vi.mocked(input.close).mockRejectedValueOnce(
    new Error("retained input handle"),
  );
  const service = new ReverseEngineeringService({
    commands: commands(input),
    digest: async () => sha256,
    run: async () => ({ stdout: "completed", stderr: "" }),
  });
  try {
    const result = await service.inspectWithObjdump({
      path: "original",
      operation: "file_headers",
    });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Expected retained cleanup");
    expect(result.error.cleanupIncomplete).toBe(true);
    expect(result.error.partialObservation).toMatchObject({
      normalized_result: { stdout: "completed" },
    });
    expect((await service.retryCleanup()).ok).toBe(true);
    expect(result.error.cleanupIncomplete).toBe(false);
    expect(input.close).toHaveBeenCalledTimes(2);
  } finally {
    await service.close();
  }
});

it("retains input until the exact owning process confirms stop", async () => {
  const input = inputOwner();
  const stop = vi
    .fn()
    .mockResolvedValueOnce({
      status: "incomplete",
      reason: "child still alive",
    })
    .mockResolvedValue({ status: "stopped" });
  const owner = { stop } as unknown as ProviderProcessSupervisor;
  const service = new ReverseEngineeringService({
    commands: commands(input),
    digest: async () => sha256,
    runOwned: async (_spawn, _limits, options) => {
      options?.retainCleanup?.(owner, {
        status: "incomplete",
        reason: "child still alive",
      });
      throw new OwnedCommandFailure(
        "process",
        "child cleanup failed",
        providerSnapshot(),
        "child still alive",
        undefined,
        ["owned-child"],
        owner,
      );
    },
  });
  try {
    const result = await service.inspectWithObjdump({
      path: "original",
      operation: "file_headers",
    });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Expected retained cleanup");
    expect(input.close).not.toHaveBeenCalled();
    expect((await service.retryCleanup()).ok).toBe(false);
    expect(input.close).not.toHaveBeenCalled();
    expect(result.error.cleanupIncomplete).toBe(true);
    expect((await service.retryCleanup()).ok).toBe(true);
    expect(input.close).toHaveBeenCalledOnce();
    expect(result.error.cleanupIncomplete).toBe(false);
  } finally {
    await service.close();
  }
});

it("closes an admitted input when cancellation interrupts preparation", async () => {
  const input = inputOwner();
  const entered = deferred();
  input.prepare = async (_digest, signal) => {
    entered.resolve();
    await new Promise<void>((_resolve, reject) =>
      signal?.addEventListener("abort", () => reject(signal.reason), {
        once: true,
      }),
    );
    throw new Error("unreachable");
  };
  const controller = new AbortController();
  const run = vi.fn(async () => ({ stdout: "", stderr: "" }));
  const service = new ReverseEngineeringService({
    commands: commands(input),
    digest: async () => sha256,
    run,
  });
  const pending = service.inspectWithObjdump(
    { path: "original", operation: "file_headers" },
    { signal: controller.signal },
  );
  await entered.promise;
  controller.abort("owned cancellation");
  try {
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok)
      expect(result.error).toMatchObject({
        _tag: "AnalysisCancelledError",
        cause: "owned cancellation",
      });
    expect(input.close).toHaveBeenCalledOnce();
    expect(run).not.toHaveBeenCalled();
  } finally {
    await service.close();
  }
});
