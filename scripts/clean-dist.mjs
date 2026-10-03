import { rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";

// tsc never deletes an output file, so a renamed or removed module would keep shipping its old
// dist artefact forever. Clean first, always.
const dist = fileURLToPath(new URL("../dist", import.meta.url));
await rm(dist, { recursive: true, force: true });
