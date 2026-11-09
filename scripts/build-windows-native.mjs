#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { importVerifierSource } from "./lib/verifier-source-loader.mjs";

const { WINDOWS_NATIVE_ARTIFACT, createWindowsNativeManifest } =
  await importVerifierSource(
    new URL("../src/domain/windowsNativeArtifact.ts", import.meta.url).href,
    import.meta.url,
  );

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const nodeVersion = "22.19.0";
const compiler = "x86_64-w64-mingw32-g++";
const windowsHost = process.platform === "win32";
const cache = join(homedir(), ".cache", "rea-windows-native");
const inspectionFixture = process.argv[2] === "--inspection-fixture";
if (process.argv.length > 3 || (process.argv.length > 2 && !inspectionFixture))
  throw new Error("Unknown Windows native build argument");
const output = inspectionFixture
  ? join(root, ".cache", "windows-native-inspection-fixture")
  : join(root, "native", "windows", "build");
let buildEnvironment = process.env;
const run = (command, args) => {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 4 * 1_024 * 1_024,
    timeout: 120_000,
    env: buildEnvironment,
    windowsHide: true,
  });
  if (result.error !== undefined)
    throw new Error(
      `Windows native build lane requires ${command}: ${result.error.message}`,
    );
  if (result.status !== 0)
    throw new Error(
      `Windows native build failed: ${result.stdout}${result.stderr}`,
    );
  return result.stdout;
};
if (process.platform !== "linux" && !windowsHost)
  throw new Error(
    "The Windows x64 artifact build lane requires Linux/MinGW-w64 or Windows/Visual Studio C++ x64 tools.",
  );
if (windowsHost) {
  const vswhere = join(
    process.env["ProgramFiles(x86)"] ?? "C:\\Program Files (x86)",
    "Microsoft Visual Studio",
    "Installer",
    "vswhere.exe",
  );
  const installation = run(vswhere, [
    "-latest",
    "-products",
    "*",
    "-requires",
    "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
    "-property",
    "installationPath",
  ]).trim();
  if (!installation)
    throw new Error(
      "Install the Visual Studio C++ x64 build tools before building the Windows addon.",
    );
  const setup = join(installation, "VC", "Auxiliary", "Build", "vcvars64.bat");
  // Only the installed toolchain's fixed setup script is interpreted by cmd.
  // Compilation below always receives an argv array and never uses a shell.
  const configured = spawnSync(
    process.env.ComSpec ?? "cmd.exe",
    ["/d", "/u", "/s", "/c", `"call "${setup}" >nul && set"`],
    {
      encoding: "utf16le",
      windowsHide: true,
      windowsVerbatimArguments: true,
      timeout: 30_000,
    },
  );
  if (configured.error || configured.status !== 0)
    throw new Error(
      `Visual Studio C++ environment setup failed: ${configured.error?.message ?? configured.status}`,
    );
  buildEnvironment = { ...process.env };
  for (const line of configured.stdout.split(/\r?\n/u)) {
    const separator = line.indexOf("=");
    if (separator > 0)
      buildEnvironment[line.slice(0, separator)] = line.slice(separator + 1);
  }
} else run(compiler, ["--version"]);
await mkdir(cache, { recursive: true });
await mkdir(output, { recursive: true });
const exists = async (path) =>
  access(path).then(
    () => true,
    () => false,
  );
const fetchBytes = async (name) => {
  const response = await fetch(
    `https://nodejs.org/dist/v${nodeVersion}/${name}`,
    {
      signal: AbortSignal.timeout(60_000),
    },
  );
  if (!response.ok)
    throw new Error(
      `Node build prerequisite download failed: ${name}: HTTP ${response.status}`,
    );
  return Buffer.from(await response.arrayBuffer());
};
const checksums = (await fetchBytes("SHASUMS256.txt")).toString("utf8");
const verifiedDownload = async (name, path) => {
  if (!(await exists(path))) await writeFile(path, await fetchBytes(name));
  const digest = createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
  const expected = checksums
    .split("\n")
    .find((line) => line.slice(66) === name)
    ?.slice(0, 64);
  if (expected === undefined || digest !== expected)
    throw new Error(`Node build prerequisite SHA-256 mismatch: ${name}`);
};
const cachedHeaders = join(
  homedir(),
  ".cache",
  "node-gyp",
  nodeVersion,
  "include",
  "node",
);
let headers = cachedHeaders;
if (!(await exists(join(headers, "node_api.h")))) {
  const archive = join(cache, `node-v${nodeVersion}-headers.tar.gz`);
  await verifiedDownload(`node-v${nodeVersion}-headers.tar.gz`, archive);
  run("tar", ["xzf", archive, "-C", cache]);
  headers = join(cache, `node-v${nodeVersion}`, "include", "node");
}
const artifact = WINDOWS_NATIVE_ARTIFACT.artifact;
// MSVC short-import libraries do not produce a correct Node import table with
// GNU ld. Generate a GNU delay-import library for the exact stable Node-API
// symbols; addon.cc binds it to the host executable, whatever its file name.
const sources = ["addon.cc", "filesystem.cc", "process.cc"];
const sourceText = (
  await Promise.all(
    sources.map((path) =>
      readFile(join(root, "native", "windows", "src", path), "utf8"),
    ),
  )
).join("\n");
const symbols = [
  ...new Set(
    [...sourceText.matchAll(/\b(napi_[a-z0-9_]+)\s*\(/gu)].map(
      (match) => match[1],
    ),
  ),
].sort();
const definition = join(cache, "node-api.def");
const library = join(cache, "libnode-api.a");
await writeFile(
  definition,
  `LIBRARY node.exe\nEXPORTS\n${symbols.join("\n")}\n`,
);
if (windowsHost) {
  const nodeLibrary = join(cache, "node-x64.lib");
  await verifiedDownload("win-x64/node.lib", nodeLibrary);
  run("cl.exe", [
    "/nologo",
    "/std:c++17",
    "/O2",
    "/EHsc",
    "/MT",
    "/LD",
    `/DNAPI_VERSION=${WINDOWS_NATIVE_ARTIFACT.nodeApiVersion}`,
    "/D_WIN32_WINNT=0x0A00",
    `/I${headers}`,
    `/Fo${output}\\`,
    "native/windows/src/addon.cc",
    inspectionFixture
      ? "tests/fixtures/windows-native-inspection-failure.cc"
      : "native/windows/src/filesystem.cc",
    "native/windows/src/process.cc",
    "/link",
    `/OUT:${join(output, artifact)}`,
    `/IMPLIB:${join(output, "rea-windows-x64.lib")}`,
    "/DELAYLOAD:node.exe",
    nodeLibrary,
    "advapi32.lib",
    "bcrypt.lib",
    "ntdll.lib",
    "delayimp.lib",
  ]);
} else {
  run("x86_64-w64-mingw32-dlltool", ["-d", definition, "-y", library]);
  run(compiler, [
    "-std=c++17",
    "-O2",
    `-DNAPI_VERSION=${WINDOWS_NATIVE_ARTIFACT.nodeApiVersion}`,
    "-D_WIN32_WINNT=0x0A00",
    "-shared",
    "-static",
    "-static-libgcc",
    "-static-libstdc++",
    "-Wl,--no-insert-timestamp",
    `-I${headers}`,
    "native/windows/src/addon.cc",
    inspectionFixture
      ? "tests/fixtures/windows-native-inspection-failure.cc"
      : "native/windows/src/filesystem.cc",
    "native/windows/src/process.cc",
    library,
    "-ladvapi32",
    "-lbcrypt",
    "-lntdll",
    "-o",
    join(output, artifact),
  ]);
}
const packageJson = JSON.parse(
  await readFile(join(root, "package.json"), "utf8"),
);
const bytes = await readFile(join(output, artifact));
const created = createWindowsNativeManifest(packageJson.version, bytes);
if (!created.ok) throw created.error;
const metadata = created.value;
await writeFile(
  join(output, "manifest.json"),
  `${JSON.stringify(metadata, null, 2)}\n`,
);
process.stdout.write(
  `${JSON.stringify({ ...metadata, artifactBytes: bytes.length })}\n`,
);
