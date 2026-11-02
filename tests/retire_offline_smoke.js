// No target JavaScript is executed. Retire scans this synthetic fixture as data.
const fs = require("fs");
const os = require("os");
const path = require("path");
const cp = require("child_process");
const root = fs.mkdtempSync(path.join(os.tmpdir(), "asfb-retire-smoke-"));
try {
  const assets = path.join(root, "assets");
  fs.mkdirSync(assets);
  fs.writeFileSync(path.join(assets, "jquery-1.6.1.js"), "/* Synthetic file-name detector fixture. */");
  const report = path.join(root, "report.json");
  const result = cp.spawnSync("/usr/local/bin/node", ["/opt/retire/lib/cli.js", "--path", assets,
    "--jsrepo", "/opt/retire-db/jsrepository-v5.json", "--outputformat", "json",
    "--outputpath", report, "--exitwith", "13"], {encoding:"utf8", timeout:20000});
  if (result.status !== 13) throw Error("Expected Retire vulnerability exit code 13: " + result.stderr);
  const data = JSON.parse(fs.readFileSync(report, "utf8"));
  if (!data.data.some(f => f.results.some(c => c.component === "jquery" && c.vulnerabilities?.length))) {
    throw Error("The installed Retire scanner did not report the known fixture");
  }
  if (data.errors.length) throw Error(JSON.stringify(data.errors));
  process.stdout.write("Retire.js installed-engine offline smoke passed\n");
} finally {
  fs.rmSync(root, {recursive:true, force:true});
}
