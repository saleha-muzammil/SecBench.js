const { expectRedos } = require("../utils");

test("ReDoS in chrono-node", () => {
  const chrono = require("chrono-node");
  expectRedos({
    run: (input) => {
      chrono.parse(input);
    },
    build: (n) => "BGR3" + " ".repeat(n) + "186'",
    n: 40000,
  });
});
