import { readFileSync, statSync, chmodSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

// tsc emits bin targets at 0644 and npm packs the modes it is handed, so a "pack is clean" check
// that does not read file modes hides an unrunnable global install. Gate on mode + existence +
// shebang, and drive off package.json's bin map so a new command cannot be forgotten.
const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const pkg = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));

for (const [name, target] of Object.entries(pkg.bin ?? {})) {
  const file = resolve(root, target);
  let mode;
  try {
    mode = statSync(file).mode;
  } catch {
    throw new Error(`bin "${name}" points at a file that does not exist: ${file}`);
  }
  const head = readFileSync(file).subarray(0, 2).toString("utf8");
  if (!head.startsWith("#!")) {
    throw new Error(`bin "${name}" has no shebang; refusing to mark it executable: ${file}`);
  }
  if ((mode & 0o111) === 0) {
    chmodSync(file, mode | 0o755);
    console.log(`mark-bins: chmod +x ${target}`);
  }
}
