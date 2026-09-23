// Two things made this entry look dead when it is not.
//
// 1. The module's default export is a through2 stream FACTORY, not a parse
//    function. Calling `conventionalCommitsParser(payload)` builds a stream,
//    hands it the payload as an options object, and parses nothing at all --
//    so the timing measured module construction. `.sync()` is what runs the
//    parser on a string.
// 2. The regex is `/^(?:\r|\n)+|(?:\r|\n)+$/g` in trimOffNewlines, which in
//    3.2.0 lives in the `trim-off-newlines` DEPENDENCY. An alternation under
//    `+` backtracks EXPONENTIALLY, not quadratically, once the trailing "b"
//    makes `$` fail: 20 repeats cost 32 ms, 24 cost 482 ms, 26 ~2 s, and the
//    original 2,000,000 repeats would not finish this century. Both images pin
//    trim-off-newlines@1.0.0 so the range does not resolve to the patched 1.0.2.
const { expectRedos } = require("../utils");

test("ReDos in conventional-commits-parser", () => {
  const conventionalCommitsParser = require("conventional-commits-parser");
  expectRedos({
    run: (input) => conventionalCommitsParser.sync(input),
    build: (n) => "b" + "\r\n".repeat(n) + "b",
    n: 26,
  });
});
