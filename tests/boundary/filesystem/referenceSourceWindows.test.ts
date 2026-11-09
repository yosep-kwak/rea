import {
  mkdtemp,
  mkdir,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { ArtifactResourceScope } from "../../../src/artifacts/ArtifactResourceScope.js";
import { readReferenceSource } from "../../../src/reference/ReferenceSourceReader.js";
import { acquireWindowsReferenceSourceFileLease } from "../../../src/reference/WindowsReferenceSourceFileLease.js";

it.skipIf(process.platform !== "win32")(
  "reads owned Windows source through native no-follow admission and excludes a junction target",
  async () => {
    const temporary = await mkdtemp(join(tmpdir(), "rea-reference-windows-"));
    const root = join(temporary, "source"),
      outside = join(temporary, "outside");
    await mkdir(root);
    await mkdir(outside);
    await writeFile(join(root, "owned.js"), "export const owned = 42;\n");
    await writeFile(
      join(outside, "external-secret.js"),
      "must not be imported",
    );
    await symlink(outside, join(root, "external-link"), "junction");
    const resources = new ArtifactResourceScope();
    try {
      const result = await readReferenceSource(root, resources);
      expect(result.ok).toBe(true);
      if (!result.ok) throw result.error;
      expect(result.value.entries).toContainEqual(
        expect.objectContaining({
          status: "read",
          kind: "file",
          path: "owned.js",
        }),
      );
      expect(
        result.value.entries.some((entry) =>
          entry.path.includes("external-secret"),
        ),
      ).toBe(false);
      expect(result.value.entries).toContainEqual(
        expect.objectContaining({ kind: "symlink", path: "external-link" }),
      );
      expect(await readFile(join(outside, "external-secret.js"), "utf8")).toBe(
        "must not be imported",
      );
      expect(resources.hasPending).toBe(false);
    } finally {
      await resources.close();
      await rm(temporary, { recursive: true, force: true });
    }
  },
);

it.skipIf(process.platform !== "win32")(
  "keeps admitted source immutable until its exact lease releases and rejects junction admission",
  async () => {
    const temporary = await mkdtemp(join(tmpdir(), "rea-reference-lease-"));
    const directory = join(temporary, "source"),
      linked = join(temporary, "junction");
    await mkdir(directory);
    const source = join(directory, "owned.txt");
    await writeFile(source, "original");
    await symlink(directory, linked, "junction");
    const resources = new ArtifactResourceScope();
    const owner = acquireWindowsReferenceSourceFileLease(source);
    try {
      await expect(writeFile(source, "forbidden")).rejects.toThrow();
      expect(await readFile(source, "utf8")).toBe("original");
      expect(() =>
        acquireWindowsReferenceSourceFileLease(join(linked, "owned.txt")),
      ).toThrow();
      expect(await resources.release(owner)).toEqual({ kind: "released" });
      await writeFile(source, "released");
      expect(await readFile(source, "utf8")).toBe("released");
    } finally {
      await resources.release(owner);
      await resources.close();
      await rm(temporary, { recursive: true, force: true });
    }
  },
);
