const { expectRedos, genstr } = require("../utils");
test("ReDos in npm-user-validate", () => {
  const npmu = require("npm-user-validate");
  expectRedos({
    run: (input) => {
      npmu.email(input);
    },
    build: (n) => "@" + genstr(n, "@") + "!",
    n: 40000,
  });

});
