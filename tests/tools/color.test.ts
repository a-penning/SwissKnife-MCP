import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { colorTool } from "../../src/tools/color.js";

type Args = Parameters<typeof colorTool.handler>[0];

function run(args: Args): CallToolResult {
  return colorTool.handler(args) as CallToolResult;
}

function structured(res: CallToolResult): Record<string, unknown> {
  expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
  return res.structuredContent as Record<string, unknown>;
}

describe("color: single-value conversions", () => {
  // Hex → rgb/hsl across 3/4/6/8-digit forms and primaries. rgb() and hsl()
  // strings derived by hand: 0x88 = 136; hsl(#ff8800) has l=0.5, s=1, and
  // hue = ((g-b)/d)*60 = (136/255)*60 ≈ 32. Pure primaries/secondaries sit at
  // 0/120/240 and 60/180/300 degrees respectively.
  it.each([
    ["#ff8800", "rgb(255, 136, 0)", "hsl(32, 100%, 50%)"],
    ["#f80", "rgb(255, 136, 0)", "hsl(32, 100%, 50%)"], // 3-digit == 6-digit
    ["#ff0000", "rgb(255, 0, 0)", "hsl(0, 100%, 50%)"],
    ["#00ff00", "rgb(0, 255, 0)", "hsl(120, 100%, 50%)"],
    ["#0000ff", "rgb(0, 0, 255)", "hsl(240, 100%, 50%)"],
    ["#ffff00", "rgb(255, 255, 0)", "hsl(60, 100%, 50%)"],
    ["#00ffff", "rgb(0, 255, 255)", "hsl(180, 100%, 50%)"],
    ["#ff00ff", "rgb(255, 0, 255)", "hsl(300, 100%, 50%)"],
    ["#808080", "rgb(128, 128, 128)", "hsl(0, 0%, 50.2%)"], // achromatic
  ])("converts hex %s to %s / %s", (hex, rgb, hsl) => {
    const out = structured(run({ input: hex }));
    expect(out.rgb).toBe(rgb);
    expect(out.hsl).toBe(hsl);
    // Any non-pure-white / non-pure-black colour has contrast > 1 in both
    // directions (a real ratio, never 1:1 unless equal luminance).
    expect(out.contrastVsBlack as number).toBeGreaterThan(1);
    expect(out.contrastVsWhite as number).toBeGreaterThan(1);
  });

  // Functional notations round-trip to the canonical hex. All inputs name the
  // same colour as #ff8800 (255,136,0); a few also exercise primaries.
  it.each([
    ["rgb(255, 136, 0)", "#ff8800"], // legacy comma
    ["rgb(255 136 0)", "#ff8800"], // modern space
    ["hsl(32, 100%, 50%)", "#ff8800"],
    ["hsl(32 100% 50%)", "#ff8800"],
    ["hwb(32 0% 0%)", "#ff8800"],
    ["rgb(255, 0, 0)", "#ff0000"],
    ["hsl(120, 100%, 50%)", "#00ff00"],
    ["hsl(240 100% 50%)", "#0000ff"],
    ["hwb(0 0% 0%)", "#ff0000"], // pure red via hwb
    ["hwb(0 100% 0%)", "#ffffff"], // whiteness 100% → white
    ["hwb(0 0% 100%)", "#000000"], // blackness 100% → black
  ])("parses %s and round-trips to %s", (input, hex) => {
    expect(structured(run({ input: input })).hex).toBe(hex);
  });

  // Named CSS colors map to their canonical hex (spot-check a spread).
  it.each([
    ["rebeccapurple", "#663399"],
    ["white", "#ffffff"],
    ["black", "#000000"],
    ["red", "#ff0000"],
    ["aqua", "#00ffff"],
    ["cyan", "#00ffff"], // alias of aqua
    ["fuchsia", "#ff00ff"],
    ["magenta", "#ff00ff"], // alias of fuchsia
    ["gray", "#808080"],
    ["grey", "#808080"], // alias of gray
    ["transparent", "#00000000"],
  ])("resolves named color %s to %s", (name, hex) => {
    expect(structured(run({ input: name })).hex).toBe(hex);
  });

  // Hex with alpha (4-digit and 8-digit). Alpha byte / 255 reasoned by hand:
  // 0x88=136 → 0.533, 0x80=128 → 0.502, 0x00=0 → 0, 0xff=255 → 1 (no suffix).
  it.each([
    ["#f008", "#ff000088", 0.53],
    ["#ff000080", "#ff000080", 0.5],
    ["#ffffff00", "#ffffff00", 0],
    ["#000f", "#000000", 1], // alpha ff drops the suffix
  ])("parses hex+alpha %s → %s (alpha≈%f)", (input, hex, alpha) => {
    const out = structured(run({ input: input }));
    expect(out.hex).toBe(hex);
    expect(out.alpha as number).toBeCloseTo(alpha, 1);
  });

  // Luminance + contrast extremes for pure white and pure black. Black has
  // luminance 0; white 1; their contrast is (1+0.05)/(0+0.05) = 21:1.
  it.each([
    ["white", 1, 21],
    ["#ffffff", 1, 21],
    ["black", 0, undefined], // white-vs-black handled by the white row
  ])("luminance/contrast extremes for %s", (value, lum, contrastVsBlack) => {
    const out = structured(run({ input: value as string }));
    expect(out.luminance).toBe(lum);
    if (contrastVsBlack !== undefined) {
      expect(out.contrastVsBlack).toBe(contrastVsBlack);
    } else {
      // Black vs black is 1:1; black vs white is the same 21:1.
      expect(out.contrastVsBlack).toBe(1);
      expect(out.contrastVsWhite).toBe(21);
    }
  });

  // hsl saturation/lightness > 100% clamp at parse time (CSS Color 4) rather
  // than emitting malformed hex. A range of over-range channels all clamp.
  it.each([
    ["hsl(0, 150%, 50%)", "#ff0000", "rgb(255, 0, 0)"],
    ["hsl(120, 200%, 50%)", "#00ff00", "rgb(0, 255, 0)"],
    ["hsl(0 0% 150%)", "#ffffff", "rgb(255, 255, 255)"], // lightness clamps to 100%
    ["hsl(0 100% 0%)", "#000000", "rgb(0, 0, 0)"], // lightness 0 → black
  ])("clamps over-range hsl %s → %s", (input, hex, rgb) => {
    const out = structured(run({ input: input }));
    expect(out.hex).toBe(hex);
    expect(out.rgb).toBe(rgb);
  });

  // rgba/hsla alpha > 1 clamps to 1 (CSS Color 4). Values are reasoned from
  // parseAlpha's clamp01.
  it.each([
    ["rgba(255, 0, 0, 5)", 1, "#ff0000"],
    ["rgba(255, 0, 0, 1.5)", 1, "#ff0000"],
    ["hsla(0, 100%, 50%, 2)", 1, "#ff0000"],
    ["rgba(255, 0, 0, 0.5)", 0.5, "#ff000080"], // in-range passes through
  ])("clamps high alpha for %s → %f", (input, alpha, hex) => {
    const out = structured(run({ input: input }));
    expect(out.alpha).toBe(alpha);
    expect(out.hex).toBe(hex);
  });

  // Negative alpha is REJECTED rather than clamped: the alpha capture group
  // `([\d.]+%?)` has no sign, so the rgba()/hsla() regex fails to match a
  // `-1` alpha and the input falls through to an error. (Contrast with hsl
  // s/l clamping, which happens post-match via clamp01.)
  it.each([["rgba(255, 0, 0, -1)"], ["hsla(0, 100%, 50%, -0.5)"]])(
    "rejects negative alpha %s",
    (input) => {
      expect(run({ input: input }).isError).toBe(true);
    },
  );

  // Hue is normalised mod 360 (CSS Color 4), so equivalent angles match.
  it.each([
    ["hsl(-90, 100%, 50%)", "hsl(270, 100%, 50%)"],
    ["hsl(360, 100%, 50%)", "hsl(0, 100%, 50%)"],
    ["hsl(420, 100%, 50%)", "hsl(60, 100%, 50%)"],
    ["hsl(-360, 100%, 50%)", "hsl(0, 100%, 50%)"],
  ])("normalises hue: %s == %s", (a, b) => {
    expect(structured(run({ input: a })).hex).toBe(
      structured(run({ input: b })).hex,
    );
  });

  // A range of distinct unparseable inputs, each a different failure mode.
  it.each([
    ["not-a-color"], // unknown token
    ["#12345"], // 5-digit hex (invalid length)
    ["#xyz"], // non-hex digits
    ["#ff88000000"], // 10-digit hex (too long)
    ["rgb(255, 0)"], // too few channels
    ["hsl(0, 100, 50)"], // missing % on s/l
    ["notacolor()"], // garbage function
    ["rgb()"], // empty function
    [""], // empty string
  ])("rejects unparseable %s", (value) => {
    expect(run({ input: value }).isError).toBe(true);
  });

  // Spot-check colours from across the full CSS Color 4 named list (148
  // entries) that the previous 32-entry subset rejected.
  it.each([
    ["chartreuse", "#7fff00"],
    ["hotpink", "#ff69b4"],
    ["dodgerblue", "#1e90ff"],
    ["tomato", "#ff6347"],
    ["limegreen", "#32cd32"],
    ["papayawhip", "#ffefd5"],
    ["mediumvioletred", "#c71585"],
    ["darkslategray", "#2f4f4f"],
    ["darkslategrey", "#2f4f4f"], // -grey alias
    ["aliceblue", "#f0f8ff"],
    ["rebeccapurple", "#663399"],
    ["yellowgreen", "#9acd32"],
    ["lightgoldenrodyellow", "#fafad2"],
  ])("knows CSS Color 4 named color %s == %s", (name, hex) => {
    expect(structured(run({ input: name })).hex, name).toBe(hex);
  });

  // Names that are NOT in the CSS list must be rejected, not guessed.
  it.each([
    ["notacolor"],
    ["bluish"],
    ["reddd"],
    ["light blue"], // space-separated isn't a CSS keyword
    ["purplish-pink"],
  ])("rejects non-CSS color name %s", (name) => {
    expect(run({ input: name }).isError).toBe(true);
  });

  it("batches an array of colors and surfaces a failures list per-item", () => {
    const out = structured(
      run({
        input: ["#ff8800", "rebeccapurple", "not-a-color", "rgb(255 0 0)"],
      }),
    );
    const results = out.results as Array<Record<string, unknown>>;
    expect(results).toHaveLength(3);
    expect(results[0]?.hex).toBe("#ff8800");
    expect(results[1]?.hex).toBe("#663399");
    expect(results[2]?.rgb).toBe("rgb(255, 0, 0)");
    const failures = out.failures as Array<{ index: number; value: string }>;
    expect(failures).toHaveLength(1);
    expect(failures[0]?.index).toBe(2);
    expect(failures[0]?.value).toBe("not-a-color");
  });

  // A range of batch shapes: all-valid, all-invalid, and mixed with the
  // failure indices landing at the ORIGINAL array positions (not the
  // compacted results positions). Expected counts/indices reasoned by hand.
  it.each([
    {
      name: "all valid",
      value: ["#ff0000", "#00ff00", "#0000ff"],
      okCount: 3,
      failIndices: [] as number[],
    },
    {
      name: "all invalid",
      value: ["nope", "also-nope", "still-nope"],
      okCount: 0,
      failIndices: [0, 1, 2],
    },
    {
      name: "failures at both ends",
      value: ["bad1", "#fff", "bad2"],
      okCount: 1,
      failIndices: [0, 2],
    },
    {
      name: "single-element array still batches",
      value: ["white"],
      okCount: 1,
      failIndices: [],
    },
  ])(
    "batch ($name): preserves original failure indices",
    ({ value, okCount, failIndices }) => {
      const out = structured(run({ input: value }));
      const results = out.results as unknown[];
      const failures = out.failures as Array<{ index: number }>;
      expect(results).toHaveLength(okCount);
      // `failures` is always an array (CC-2), empty when nothing failed.
      expect(Array.isArray(failures)).toBe(true);
      expect(failures.map((f) => f.index)).toEqual(failIndices);
    },
  );

  it("always emits failures as an array (empty when nothing failed) — CC-2", () => {
    const out = structured(run({ input: ["#ff0000", "#00ff00"] }));
    expect(out.failures).toEqual([]);
    expect((out.results as unknown[]).length).toBe(2);
  });

  it("single result echoes the input back (CC-3: batch + single parity)", () => {
    const out = structured(run({ input: "#ff8800" }));
    expect(out.input).toBe("#ff8800");
  });

  // Mixed legacy/modern delimiters in rgb()/hsl() where a COMMA precedes a
  // space-separated tail — the heuristic detects this form and emits the
  // helpful "commas OR whitespace" pointer.
  it.each([["hsl(32, 100% 50%)"], ["rgb(255, 136 0)"]])(
    "rejects mixed comma-then-space delimiters in %s with a pointer",
    (value) => {
      const res = run({ input: value });
      expect(res.isError).toBe(true);
      expect(JSON.stringify(res.content)).toMatch(/commas OR whitespace/);
    },
  );

  // The space-then-comma form (and other mixed shapes) still ERRORS — it just
  // falls through to the generic parse error rather than the tailored
  // mixed-delimiter pointer, because the detector heuristic only catches the
  // comma-first shape. Rejection is what matters here.
  it.each([["hsl(32 100%, 50%)"], ["rgb(255 136, 0)"]])(
    "rejects mixed space-then-comma delimiters in %s",
    (value) => {
      expect(run({ input: value }).isError).toBe(true);
    },
  );

  // WCAG pass/fail flags across the contrast bands. Thresholds (WCAG 2.1):
  // aaLarge ≥3, aaNormal ≥4.5, aaaLarge ≥4.5, aaaNormal ≥7. White-on-black is
  // 21:1 (passes all); white-on-white is 1:1 (fails all).
  it("white-on-black passes every WCAG band", () => {
    const out = structured(run({ input: "#ffffff" }));
    const w = out.wcagVsBlack as Record<string, boolean>;
    expect(w.aaLarge).toBe(true);
    expect(w.aaNormal).toBe(true);
    expect(w.aaaLarge).toBe(true);
    expect(w.aaaNormal).toBe(true);
  });

  it("white-on-white (1:1) fails every WCAG band", () => {
    const out = structured(run({ input: "#ffffff" }));
    const w = out.wcagVsWhite as Record<string, boolean>;
    expect(w.aaLarge).toBe(false);
    expect(w.aaNormal).toBe(false);
    expect(w.aaaLarge).toBe(false);
    expect(w.aaaNormal).toBe(false);
  });

  // `against` pairwise contrast across a range of pairs. Reasoned bounds:
  // identical colours → 1:1 (fails all); black/white → 21:1 (passes all);
  // a mid grey vs white sits between, and the relation is symmetric.
  it.each([
    ["#000000", "#ffffff", 21, true],
    ["#ffffff", "#000000", 21, true], // symmetric
    ["#777777", "#777777", 1, false], // identical → 1:1
    ["#000000", "#000000", 1, false],
  ])(
    "`against` contrast(%s, %s) ≈ %f (aaNormal=%s)",
    (value, against, contrast, aaNormal) => {
      const out = structured(run({ input: value, against }));
      expect(out.contrast).toBeCloseTo(contrast, 1);
      expect((out.wcag as Record<string, boolean>).aaNormal).toBe(aaNormal);
    },
  );

  it("`against` produces a contrast > 1 for distinct colors", () => {
    const out = structured(run({ input: "#777777", against: "#ffffff" }));
    expect(out.contrast as number).toBeGreaterThan(1);
    expect(typeof (out.wcag as Record<string, unknown>).aaNormal).toBe(
      "boolean",
    );
  });

  // `against` rejects array primaries and unparseable colours on either side.
  it.each([
    [["#000", "#fff"] as string[] | string, "#888"], // array primary
    ["#000", "not-a-color"], // bad `against`
    ["not-a-color", "#fff"], // bad primary
  ])("`against` rejects bad input (%o, %s)", (value, against) => {
    const res = run({ input: value, against } as Args);
    expect(res.isError).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// rgb() parsing is consistent with hsl()/hwb(): out-of-range channels
// clamp (negatives → 0, > max → max), and percentage notation is accepted
// in both legacy and modern syntax. CSS Color 4 spec.
// ---------------------------------------------------------------------------
describe("color: rgb()/rgba() parity with hsl()/hwb()", () => {
  it("clamps out-of-range rgb channels instead of erroring (like hsl/hwb)", () => {
    // hsl already clamps; rgb should too rather than rejecting with 0-255.
    expect(structured(run({ input: "rgb(300 0 0)" })).hex).toBe("#ff0000");
    expect(structured(run({ input: "rgb(0 999 0)" })).hex).toBe("#00ff00");
    expect(structured(run({ input: "rgb(300, 0, 0)" })).hex).toBe("#ff0000");
  });

  it("clamps negative rgb channels to zero rather than failing to parse", () => {
    expect(structured(run({ input: "rgb(-10 0 0)" })).hex).toBe("#000000");
    expect(structured(run({ input: "rgb(-10, -20, -30)" })).hex).toBe(
      "#000000",
    );
  });

  it("treats too-high and negative channels consistently (both clamp, not two error modes)", () => {
    // Today: rgb(300 0 0) -> "must be 0-255", rgb(-10 0 0) -> "expected #hex".
    // Two different failures for the same class of mistake. Both should clamp.
    const high = run({ input: "rgb(300 0 0)" });
    const low = run({ input: "rgb(-10 0 0)" });
    expect(high.isError).toBe(low.isError);
    expect(high.isError).toBeFalsy();
  });

  it("accepts percentage channels in modern (space) syntax", () => {
    // 20% -> 51 (0x33), 40% -> 102 (0x66), 60% -> 153 (0x99) — all exact.
    expect(structured(run({ input: "rgb(20% 40% 60%)" })).hex).toBe("#336699");
    expect(structured(run({ input: "rgb(100% 100% 100%)" })).hex).toBe(
      "#ffffff",
    );
    expect(structured(run({ input: "rgb(0% 0% 0%)" })).hex).toBe("#000000");
  });

  it("accepts percentage channels in legacy (comma) syntax", () => {
    expect(structured(run({ input: "rgb(20%, 40%, 60%)" })).hex).toBe(
      "#336699",
    );
    const out = structured(run({ input: "rgba(100%, 0%, 0%, 0.5)" }));
    expect(out.hex).toBe("#ff000080");
    expect(out.alpha).toBeCloseTo(0.5, 1);
  });

  it("is internally consistent: identical out-of-range handling for rgb vs hsl", () => {
    // The whole point — the same out-of-range mistake should not succeed in
    // one functional notation and error in another.
    const rgb = run({ input: "rgb(300 0 0)" });
    const hsl = run({ input: "hsl(0 150% 50%)" });
    expect(rgb.isError).toBe(hsl.isError);
  });
});
