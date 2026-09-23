// The payload was always right -- EMPTY_ROW_REGEXP,
// /^\s*(?:''|"")?\s*(?:,\s*(?:''|"")?\s*)*$/, costs ~1 s on 30k leading spaces
// in 4.3.5 and ~0 in 4.3.6. What failed was the assertion: it sat inside the
// stream's "end" handler with nothing telling jest to wait, so the test
// function returned before parsing finished and the expect() either never ran
// or threw after the test had already been reported. Parsing is async here, so
// the test has to return a promise that settles on "end"/"error".
const { assertRedos } = require("../utils");

const parse = (input) =>
  new Promise((resolve, reject) => {
    const csv = require("fast-csv");
    const start = process.hrtime.bigint();
    csv
      .parse({ ignoreEmpty: true, delimiter: "\t" })
      .on("error", reject)
      .on("data", () => {})
      .on("end", () => resolve(Number(process.hrtime.bigint() - start) / 1e6))
      .end(input);
  });

const build = (n) => " ".repeat(n) + "x\n";

test("ReDos in fast-csv", async () => {
  const n = 30000;
  // Same three-sample shape as utils.expectRedos, done by hand because the
  // parse is async and expectRedos drives a synchronous `run`.
  await parse(build(Math.floor(n / 64)));                       // warm up
  const baselineMs = await parse(build(Math.floor(n / 8)));
  const halfMs = await parse(build(Math.floor(n / 2)));
  const attackMs = await parse(build(n));
  assertRedos({
    attackMs,
    baselineMs,
    halfMs,
    ratio: attackMs / Math.max(baselineMs, 1e-3),
    scaling: attackMs / Math.max(halfMs, 1e-3),
    n,
    nBase: Math.floor(n / 8),
    nHalf: Math.floor(n / 2),
  });
}, 60000);
