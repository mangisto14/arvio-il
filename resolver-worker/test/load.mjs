// Transpiles the worker's TypeScript sources to ES modules for node:test.
import { mkdtempSync, readFileSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

const src = fileURLToPath(new URL("../src/", import.meta.url));
const out = mkdtempSync(join(tmpdir(), "arvio-relay-test-"));
for (const file of readdirSync(src).filter((name) => name.endsWith(".ts"))) {
  const { outputText } = ts.transpileModule(readFileSync(join(src, file), "utf8"), {
    compilerOptions: { module: ts.ModuleKind.ES2022, target: ts.ScriptTarget.ES2022 }
  });
  writeFileSync(join(out, file.replace(/\.ts$/, ".mjs")), outputText.replace(/from "\.\/([\w-]+)"/g, 'from "./$1.mjs"'));
}

export const relay = await import(pathToFileURL(join(out, "mediaRelay.mjs")).href);
export const worker = (await import(pathToFileURL(join(out, "index.mjs")).href)).default;
