const { expectRedos, genstr } = require("../utils");

test("ReDos in mobile-detect", () => {
  const MobileDetect = require("mobile-detect");
  expectRedos({
    run: (input) => {
      const md = new MobileDetect(input);
      md.phone();
    },
    build: (n) => genstr(n, "Dell"),
    n: 12500,
  });
});
