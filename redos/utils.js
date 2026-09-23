/**
 * Copyright 2017 Software Lab, TU Darmstadt, Germany
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Created by Cristian-Alexandru Staicu on 29.06.17.
 * Special thanks to the Node Security Team for sharing similar code on their website!
 */
function genstr(len, chr) {
  var result = "";
  for (let i = 0; i <= len; i++) {
    result = result + chr;
  }
  return result;
}

function measureTime(f, print) {
  var start = process.hrtime();
  f();
  var end = process.hrtime(start);
  // if (print === false) {

  // } else {
  //     console.info("Execution time (hr): %ds %dms", end[0], end[1] / 1000000);
  // }
  return end;
}

function monkeyPatch() {
  var oldReplace = String.prototype.replace;
  String.prototype.replace = function () {
    var start = process.hrtime();
    var res = oldReplace.apply(this, arguments);
    var end = process.hrtime(start);
    if (this instanceof String) {
      console.info(
        "Execution time (hr): " + end[0] + "s " + end[1] / 1000000 + "ms"
      );
      console.info(
        getCallerFile() + " replace " + arguments[0] + " " + limit(this)
      );
    }
    return res;
  };

  var oldMatch = String.prototype.match;
  String.prototype.match = function () {
    var start = process.hrtime();
    var res = oldMatch.apply(this, arguments);
    var end = process.hrtime(start);
    if (this instanceof String) {
      console.info("Execution time (hr): %ds %dms", end[0], end[1] / 1000000);
      console.log(
        getCallerFile() + " match " + arguments[0] + " " + limit(this)
      );
    }
    return res;
  };

  var oldSplit = String.prototype.split;
  String.prototype.split = function () {
    var start = process.hrtime();
    var res = oldSplit.apply(this, arguments);
    var end = process.hrtime(start);
    if (this instanceof String) {
      console.info("Execution time (hr): %ds %dms", end[0], end[1] / 1000000);
      console.log(
        getCallerFile() + " split " + arguments[0] + " " + limit(this)
      );
    }
    return res;
  };

  var oldSearch = String.prototype.search;
  String.prototype.search = function () {
    var start = process.hrtime();
    var res = oldSearch.apply(this, arguments);
    var end = process.hrtime(start);
    if (this instanceof String) {
      console.info("Execution time (hr): %ds %dms", end[0], end[1] / 1000000);
      console.log(
        getCallerFile() + " search " + arguments[0] + " " + limit(this)
      );
    }
    return res;
  };

  var oldExec = RegExp.prototype.exec;
  RegExp.prototype.exec = function () {
    var start = process.hrtime();
    var res = oldExec.apply(this, arguments);
    var end = process.hrtime(start);
    if (console.log) {
      console.info("Execution time (hr): %ds %dms", end[0], end[1] / 1000000);
      console.log(
        getCallerFile() + " exec " + limit(arguments[0]) + " " + this
      );
    }
    return res;
  };

  var oldTest = RegExp.prototype.test;
  RegExp.prototype.test = function () {
    var start = process.hrtime();
    var res = oldTest.apply(this, arguments);
    var end = process.hrtime(start);
    if (console.log) {
      console.info("Execution time (hr): %ds %dms", end[0], end[1] / 1000000);
      console.log(
        getCallerFile() + " test " + limit(arguments[0]) + " " + this
      );
    }
    return res;
  };

  function limit(a) {
    if (a.length && a.length < 50) return a;
    return "TOO_LONG";
  }

  function getCallerFile() {
    try {
      var err = new Error();
      var callerfile;
      var currentfile;

      Error.prepareStackTrace = function (err, stack) {
        return stack;
      };

      currentfile = err.stack.shift().getFileName();

      while (err.stack.length) {
        callerfile = err.stack.shift().getFileName();
        if (currentfile !== callerfile) return callerfile;
      }
    } catch (err) {}
    return undefined;
  }
}

/* ---------------------------------------------------------------------------
 * Ratio oracle.
 *
 * measureTime + `expect(time).toBeGreaterThan(1)` is wrong in both directions:
 *
 *   - it measures the FIRST call, so lazy module init lands inside the timed
 *     region. browserslist spends 1161 ms getting to its first regex, so the
 *     FIXED version "passes" the exploit and the entry is written off as
 *     `baseline-already-vulnerable: image-not-fixed`.
 *   - one absolute second is not a property of the package. ssri, tmpl,
 *     normalize-url, npm-user-validate, method-override and valid-email each
 *     blow up from ~0 ms to 441-971 ms when the fix is reverted -- a real
 *     catastrophic backtrack that the 1 s bar records as "does not reproduce".
 *
 * What actually distinguishes ReDoS is SHAPE, not wall clock: cost that grows
 * super-linearly in the input size. So time the same call at three sizes after
 * warmup and report both growth factors:
 *
 *   ratio   = t(n) / t(n/8)   -- linear ~8,  quadratic ~64,  exponential huge
 *   scaling = t(n) / t(n/2)   -- linear ~2,  quadratic ~4,   exponential huge
 *
 * A verdict needs attackMs >= 50 (fast enough and it cannot be backtracking),
 * ratio >= 20 (else the package is uniformly slow, not input-triggered) and
 * scaling >= 3 (else the cost is linear in input size, not catastrophic).
 * Those are the same thresholds retest_redos.py's classify() applies, and the
 * numbers are self-contained: no comparison against a second container run.
 * ------------------------------------------------------------------------- */

var REDOS_DEFAULTS = {
  minAttackMs: 50, // below this, nothing was backtracking
  minRatio: 20, // t(n)/t(n/8); linear is ~8
  minScaling: 3, // t(n)/t(n/2); linear is ~2
  baselineDiv: 8, // the benign sample is this many times smaller
  warmup: 3, // calls discarded before timing (module init + JIT)
  reps: 3, // best-of for the cheap samples; the attack runs once
  budgetMs: 10000, // a benign sample slower than this is uniformly slow
};

function _opt(spec, key) {
  return spec && spec[key] !== undefined ? spec[key] : REDOS_DEFAULTS[key];
}

function _timeOnce(run, input) {
  var s = process.hrtime.bigint();
  run(input);
  return Number(process.hrtime.bigint() - s) / 1e6;
}

// Best-of-N. The minimum is the sample least polluted by GC and scheduling,
// which matters because these are the denominators of both growth factors --
// an inflated baseline hides a real blow-up.
function _timeBest(run, input, reps) {
  var best = Infinity;
  for (var i = 0; i < reps; i++) best = Math.min(best, _timeOnce(run, input));
  return best;
}

/**
 * measureRedos({run, build, n}) -> metrics
 *
 *   run(input)  calls the vulnerable API with a payload; nothing else.
 *   build(n)    constructs the payload of size n. Must be pure -- it is called
 *               four times at three different sizes.
 *   n           the original attack size.
 */
function measureRedos(spec) {
  var run = spec.run;
  var build = spec.build;
  var n = spec.n;
  var div = _opt(spec, "baselineDiv");
  var reps = _opt(spec, "reps");
  var budget = _opt(spec, "budgetMs");
  var nBase = Math.max(1, Math.floor(n / div));
  var nHalf = Math.max(1, Math.floor(n / 2));

  // Warm up on a payload far below the baseline size, so module init, lazy
  // regex compilation and JIT tiering all happen OUTSIDE every timed region.
  var warmInput = build(Math.max(1, Math.floor(n / (div * 8))));
  for (var i = 0; i < _opt(spec, "warmup"); i++) {
    try {
      run(warmInput);
    } catch (e) {
      /* a payload the fixed version rejects outright still warms the module */
    }
  }

  var baselineMs = _timeBest(run, build(nBase), reps);
  // Uniformly slow: the small payload already blew the budget, so escalating to
  // n/2 and n buys nothing but minutes. Report flat growth -- which is exactly
  // what "slow for every input" means -- instead of timing it three more times.
  if (baselineMs > budget) {
    return {
      attackMs: baselineMs, baselineMs: baselineMs, halfMs: baselineMs,
      ratio: 1, scaling: 1, n: n, nBase: nBase, nHalf: nHalf,
      truncated: "baseline exceeded budgetMs; package is slow for every input",
    };
  }
  var halfMs = _timeBest(run, build(nHalf), 1);
  var attackMs = _timeOnce(run, build(n));

  var eps = 1e-3; // sub-microsecond samples must not divide to Infinity
  return {
    attackMs: attackMs,
    baselineMs: baselineMs,
    halfMs: halfMs,
    ratio: attackMs / Math.max(baselineMs, eps),
    scaling: attackMs / Math.max(halfMs, eps),
    n: n, nBase: nBase, nHalf: nHalf,
  };
}

/**
 * measureRedosPair({run, benign, attack}) -> metrics
 *
 * For payloads with no single size knob: two concrete inputs of comparable
 * length, one pathological and one not. There is no size axis, so `scaling` is
 * null and the verdict rests on the benign/attack ratio alone.
 */
function measureRedosPair(spec) {
  var run = spec.run;
  var reps = _opt(spec, "reps");
  for (var i = 0; i < _opt(spec, "warmup"); i++) {
    try {
      run(spec.benign);
    } catch (e) {}
  }
  var baselineMs = _timeBest(run, spec.benign, reps);
  var attackMs = _timeOnce(run, spec.attack);
  return {
    attackMs: attackMs,
    baselineMs: baselineMs,
    halfMs: null,
    ratio: attackMs / Math.max(baselineMs, 1e-3),
    scaling: null,
  };
}

function _fmt(v) {
  return v === null || v === undefined ? "n/a" : v.toFixed(3) + "ms";
}

// Throws with the full picture, never a bare "expected true". A failing ReDoS
// assertion is a claim about the benchmark, so the numbers behind it have to be
// in the failure message -- that text is what ends up in the campaign report.
function assertRedos(m, spec) {
  var why = null;
  if (m.attackMs < _opt(spec, "minAttackMs")) {
    why = "too fast to be backtracking";
  } else if (m.ratio < _opt(spec, "minRatio")) {
    why = "uniformly slow, not input-triggered";
  } else if (m.scaling !== null && m.scaling < _opt(spec, "minScaling")) {
    why = "linear in input size, not catastrophic";
  }
  if (why) {
    throw new Error(
      "no ReDoS: " + why + " (attack " + _fmt(m.attackMs) +
        " at n=" + m.n + ", benign baseline " + _fmt(m.baselineMs) +
        " at n=" + m.nBase + " -> ratio " + m.ratio.toFixed(1) + "x" +
        (m.scaling === null ? "" : ", scaling " + m.scaling.toFixed(1) + "x") +
        ")"
    );
  }
  return m;
}

function expectRedos(spec) {
  return assertRedos(measureRedos(spec), spec);
}

function expectRedosPair(spec) {
  return assertRedos(measureRedosPair(spec), spec);
}

module.exports.genstr = genstr;
module.exports.measureTime = measureTime;
module.exports.monkeyPatch = monkeyPatch;
module.exports.measureRedos = measureRedos;
module.exports.measureRedosPair = measureRedosPair;
module.exports.expectRedos = expectRedos;
module.exports.expectRedosPair = expectRedosPair;
module.exports.assertRedos = assertRedos;
