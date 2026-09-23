// This entry could not reproduce under node for two independent reasons.
//
// 1. Wrong entry point. html-dom-parser ships two builds: index.js ->
//    lib/html-to-dom-server.js (htmlparser2) for node, and, via package.json's
//    "browser" map, lib/html-to-dom-client.js -> lib/domparser.js for the
//    browser. HEAD_REGEX/BODY_REGEX -- the regexes patch.txt touches -- exist
//    only in the browser build, so a plain require("html-dom-parser") under
//    jest never loads the vulnerable code at all.
// 2. Wrong payload. "<head" + " S".repeat(n) can never match
//    /<head[\s\S]*>[\s\S]*<\/head>/i: there is no ">" anywhere, so the match
//    fails at offset 0 and the scan is linear. The quadratic blow-up needs many
//    ">" for [\s\S]*> to backtrack over, and a first tag of <html> so
//    domparser.js takes the branch that tests HEAD_REGEX.
//
// With both corrected: 0.1.2 costs 13 ms / 160 ms / 1363 ms at n = 5k / 20k /
// 60k, and 0.1.3 stays flat at ~2 ms.
const { expectRedos } = require("../utils");

// jsdom is installed into the package's own node_modules by the Dockerfile, so
// prefer the plain specifier and fall back to that path when the test is run
// from a directory that does not have its own copy.
let JSDOM;
try {
  ({ JSDOM } = require("jsdom"));
} catch (e) {
  ({ JSDOM } = require("html-dom-parser/node_modules/jsdom"));
}

test("ReDos in html-dom-parser", () => {
  const dom = new JSDOM("<!doctype html><html><body></body></html>");
  // domparser.js calls isIE() (which reads navigator.userAgent) at module load
  // and DOMParser at call time, so the globals have to exist before the require.
  global.window = dom.window;
  global.document = dom.window.document;
  global.navigator = dom.window.navigator;
  global.DOMParser = dom.window.DOMParser;
  global.HTMLElement = dom.window.HTMLElement;
  const parse = require("html-dom-parser/lib/html-to-dom-client");

  expectRedos({
    run: (input) => {
      parse(input);
    },
    build: (n) => "<html><head" + ">".repeat(n),
    n: 60000,
  });
});
