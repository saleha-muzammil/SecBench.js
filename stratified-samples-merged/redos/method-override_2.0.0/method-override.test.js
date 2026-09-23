const { expectRedos } = require("../utils");

test("ReDos in method-override", () => {
  const methodOverride = require("method-override");
  const middleware = methodOverride();
  expectRedos({
    run: (input) => {
      middleware(
        {
          headers: { "x-http-method-override": input },
          method: "POST",
        },
        {
          getHeader: () => {
            return "";
          },
          setHeader: () => {},
        },
        () => {}
      );
    },
    build: (n) => " ".repeat(n),
    n: 40000,
  });
});
