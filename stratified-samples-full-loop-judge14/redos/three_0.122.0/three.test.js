const { expectRedos, genstr } = require("../utils");

test("ReDos in three", () => {
  const three = require("three");
  const Color = three.Color;
  expectRedos({
    run: (input) => {
      new Color(input);
    },
    build: (n) => "rgb(" + genstr(n, " ") + "",
    n: 50000,
  });
});
