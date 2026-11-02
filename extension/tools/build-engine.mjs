// Builds the Rust engine for WebAssembly and puts it where the extension loads it:
//   node extension/tools/build-engine.mjs
// Needs Rust with the wasm32-unknown-unknown target (rustup target add wasm32-unknown-unknown).

import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const cargoHome = join(homedir(), ".cargo", "bin", process.platform === "win32" ? "cargo.exe" : "cargo");
const cargo = existsSync(cargoHome) ? cargoHome : "cargo";

execFileSync(cargo, ["build", "--release", "--target", "wasm32-unknown-unknown", "-p", "shadowlens-engine-wasm"], {
  cwd: join(root, "engine"),
  stdio: "inherit",
  env: { ...process.env, PATH: `${dirname(cargoHome)}${process.platform === "win32" ? ";" : ":"}${process.env.PATH}` },
});
const built = join(root, "engine", "target", "wasm32-unknown-unknown", "release", "shadowlens_engine_wasm.wasm");
const target = join(root, "extension", "src", "engine", "shadowlens_engine.wasm");
copyFileSync(built, target);
console.log(`engine: ${target} (${Math.round(statSync(target).size / 1024)} KB)`);
