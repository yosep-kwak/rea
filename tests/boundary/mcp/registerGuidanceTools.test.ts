import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { Ajv2020, type AnySchema } from "ajv/dist/2020.js";
import { afterEach, expect, it } from "vitest";
import { ArtifactResourceScope } from "../../../src/artifacts/ArtifactResourceScope.js";
import {
  readGuidanceSectionOutputSchema,
  searchGuidanceInputSchema,
  searchGuidanceOutputSchema,
} from "../../../src/contracts/guidanceContracts.js";
import { EvidenceMcpServer } from "../../../src/server/EvidenceMcpServer.js";
import { registerGuidanceTools } from "../../../src/server/registerGuidanceTools.js";
import { ToolResultDelivery } from "../../../src/server/ToolResultDelivery.js";

const open: {
  client: Client;
  server: EvidenceMcpServer;
  resources: ArtifactResourceScope;
}[] = [];
const guidanceOutput = <T>(
  schema: { parse(value: unknown): T },
  value: unknown,
): T => {
  return schema.parse(value);
};
afterEach(async () => {
  await Promise.all(
    open
      .splice(0)
      .flatMap(({ client, server, resources }) => [
        client.close(),
        server.close(),
        resources.close(),
      ]),
  );
});

it("advertises strict provider-free contracts and returns packaged guide results over MCP", async () => {
  const server = new EvidenceMcpServer(
    { name: "guidance-test", version: "1" },
    { capabilities: { tools: { listChanged: true } } },
    undefined,
    new ToolResultDelivery(1024 * 1024),
  );
  const resources = new ArtifactResourceScope();
  registerGuidanceTools(server, resources);
  const client = new Client({ name: "guidance-client", version: "1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  open.push({ client, server, resources });

  const listed = await client.listTools();
  expect(listed.tools.map(({ name }) => name)).toEqual(
    expect.arrayContaining(["search_guidance", "read_guidance_section"]),
  );
  const validateOutput = (name: string, value: unknown) => {
    const schema = listed.tools.find(
      (tool) => tool.name === name,
    )?.outputSchema;
    expect(schema).toBeDefined();
    const validate = new Ajv2020({ strict: false }).compile(
      schema as AnySchema,
    );
    expect(validate(value), JSON.stringify(validate.errors)).toBe(true);
  };
  expect(
    searchGuidanceInputSchema.safeParse({
      query: "module",
      unexpected: true,
    }).success,
  ).toBe(false);
  const invalidLocator = await client.callTool({
    name: "read_guidance_section",
    arguments: { locator: "../../outside.md" },
  });
  expect(invalidLocator.isError).toBe(true);
  const invalidLimit = await client.callTool({
    name: "search_guidance",
    arguments: { query: "module", limit: 21 },
  });
  expect(invalidLimit.isError).toBe(true);
  const response = await client.callTool({
    name: "search_guidance",
    arguments: { query: "exact JavaScript module" },
  });
  expect(response.isError).not.toBe(true);
  validateOutput("search_guidance", response.structuredContent);
  const parsed = guidanceOutput(
    searchGuidanceOutputSchema,
    response.structuredContent,
  );
  expect(parsed).toMatchObject({
    status: "matches",
    source: "installed_rea_guidance",
  });
  if (parsed.status !== "matches") throw new Error("Expected guidance matches");
  const selected = parsed.matches.find(
    ({ heading }) => heading === "Read a module without repeating analysis",
  );
  expect(selected).toBeDefined();
  const section = await client.callTool({
    name: "read_guidance_section",
    arguments: { locator: selected?.locator },
  });
  expect(section.isError).not.toBe(true);
  validateOutput("read_guidance_section", section.structuredContent);
  expect(
    guidanceOutput(readGuidanceSectionOutputSchema, section.structuredContent),
  ).toMatchObject({
    status: "section",
    heading: selected?.heading,
    source: "installed_rea_guidance",
  });
  const firstPage = await client.callTool({
    name: "search_guidance",
    arguments: { query: "module", limit: 1 },
  });
  const firstResult = guidanceOutput(
    searchGuidanceOutputSchema,
    firstPage.structuredContent,
  );
  if (firstResult.status !== "matches" || firstResult.next_cursor === undefined)
    throw new Error("Expected a guidance continuation token");
  const nextPage = await client.callTool({
    name: "search_guidance",
    arguments: {
      query: "module",
      limit: 1,
      cursor: firstResult.next_cursor,
    },
  });
  expect(
    guidanceOutput(searchGuidanceOutputSchema, nextPage.structuredContent),
  ).toMatchObject({ status: "matches", offset: 1 });
  validateOutput("search_guidance", nextPage.structuredContent);
  const absent = await client.callTool({
    name: "search_guidance",
    arguments: { query: "absentguidanceword5837294" },
  });
  expect(absent.isError).not.toBe(true);
  expect(absent.structuredContent).toMatchObject({ status: "no_matches" });
  validateOutput("search_guidance", absent.structuredContent);
  const staleLocator =
    "rea-guide-v1." +
    Buffer.from(
      JSON.stringify({
        ...JSON.parse(
          Buffer.from(
            selected!.locator.slice("rea-guide-v1.".length),
            "base64url",
          ).toString(),
        ),
        bundle: "0".repeat(64),
      }),
    ).toString("base64url");
  const stale = await client.callTool({
    name: "read_guidance_section",
    arguments: { locator: staleLocator },
  });
  expect(stale.isError).not.toBe(true);
  expect(stale.structuredContent).toMatchObject({ status: "stale_locator" });
  validateOutput("read_guidance_section", stale.structuredContent);
});
