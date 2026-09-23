const { expectRedos } = require("../utils");
test("ReDoS in tmpl", () => {
  const tmpl = require("tmpl");
  expectRedos({
    run: (input) => {
      tmpl(input, { day: "tomorrow" });
    },
    build: (n) => "hello, " + "{".repeat(7 * n) + "day",
    n: 10000,
  });

});
