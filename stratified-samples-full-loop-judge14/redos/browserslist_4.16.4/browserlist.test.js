const { expectRedos } = require("../utils");

test("ReDoS in browserslist", () => {
  const browserslist = require("browserslist");
  expectRedos({
    run: (input) => {
      try {
        browserslist(input);
      } catch (e) {}
    },
    build: (n) => "> " + "1".repeat(n) + "!",
    n: 25000,
  });
});
