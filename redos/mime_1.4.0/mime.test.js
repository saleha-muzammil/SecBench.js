// mime@2.0.0 renamed `lookup()` to `getType()` and dropped the old name, so a
// hard-coded `mime.lookup` throws a TypeError on the fixed tree (mime@2.0.3)
// before anything is measured. Both trees expose one of the two names.
test(
  "ReDos in mime",
  () => {
    const genstr = require("../utils").genstr;
    const measureTime = require("../utils").measureTime;
    const mime = require("mime");
    const lookup =
      typeof mime.getType === "function"
        ? mime.getType.bind(mime)
        : mime.lookup.bind(mime);
    let str = genstr(81750, "5") + "";
    let t = measureTime(function () {
      lookup(str);
    });
    let time = t[0] + t[1] / 1000000000;
    expect(time).toBeGreaterThan(1);
  },
  60000
);
