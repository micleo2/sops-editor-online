// Inlines wasm_exec.js and the gzipped WebAssembly module into the page template.
// Usage: node scripts/inline.mjs <template.html> <wasm_exec.js> <core.wasm.gz> > index.html
import { readFileSync } from "node:fs";

const [template, wasmExec, wasmGz] = process.argv.slice(2);
if (!wasmGz) {
  console.error("usage: node scripts/inline.mjs <template.html> <wasm_exec.js> <core.wasm.gz>");
  process.exit(2);
}

let html = readFileSync(template, "utf8");
const exec = readFileSync(wasmExec, "utf8");
const b64 = readFileSync(wasmGz).toString("base64");

for (const marker of ["/*WASM_EXEC_JS*/", "__WASM_GZ_BASE64__"]) {
  if (html.split(marker).length !== 2) throw new Error(`expected exactly one ${marker} in ${template}`);
}
if (exec.includes("</script")) throw new Error("wasm_exec.js unexpectedly contains </script");

html = html.replace("/*WASM_EXEC_JS*/", () => exec).replace("__WASM_GZ_BASE64__", () => b64);
process.stdout.write(html);
