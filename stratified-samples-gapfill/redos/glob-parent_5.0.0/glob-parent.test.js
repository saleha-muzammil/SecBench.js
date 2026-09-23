// The `enclosure` regex reverted by patch.txt is quadratic, not exponential:
// n=3000 costs ~4ms, n=10000 ~58ms, n=50000 ~2.6s. The original payload was an
// order of magnitude below the 1s bar, so the reverted (vulnerable) tree looked
// identical to the fixed one.
test(
  "ReDos in glob-parent",
  () => {
    const genstr = require("../utils").genstr;
    const measureTime = require("../utils").measureTime;
    const globParent = require("glob-parent");
    let attack_str = "{" + genstr(50000, "/");
    let t = measureTime(function () {
      globParent(attack_str);
    });
    let time = t[0] + t[1] / 1000000000;
    expect(time).toBeGreaterThan(1);
  },
  60000
);
