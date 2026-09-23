const { expectRedos } = require("../utils");

test("ReDoS in cejs", () => {
  const c = require("cejs");
  expectRedos({
    run: (input) => {
      c.run(input);
    },
    build: (n) => ".".repeat(n) + "\n%",
    n: 7000000,
  });
});
