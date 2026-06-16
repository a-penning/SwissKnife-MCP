interface Rgba {
  r: number;
  g: number;
  b: number;
  a: number;
}

// Full CSS Color Module 4 named-color list (148 entries) plus `transparent`.
// Source: https://www.w3.org/TR/css-color-4/#named-colors. The previous
// 32-entry subset rejected common colors (chartreuse, hotpink, dodgerblue,
// …) despite them being valid CSS. We include `cyan`/`magenta` as aliases
// of `aqua`/`fuchsia` and `grey` as alias of `gray` for parity with how
// CSS resolves these.
const NAMED_COLORS: Record<string, string> = {
  aliceblue: "#f0f8ff",
  antiquewhite: "#faebd7",
  aqua: "#00ffff",
  aquamarine: "#7fffd4",
  azure: "#f0ffff",
  beige: "#f5f5dc",
  bisque: "#ffe4c4",
  black: "#000000",
  blanchedalmond: "#ffebcd",
  blue: "#0000ff",
  blueviolet: "#8a2be2",
  brown: "#a52a2a",
  burlywood: "#deb887",
  cadetblue: "#5f9ea0",
  chartreuse: "#7fff00",
  chocolate: "#d2691e",
  coral: "#ff7f50",
  cornflowerblue: "#6495ed",
  cornsilk: "#fff8dc",
  crimson: "#dc143c",
  cyan: "#00ffff",
  darkblue: "#00008b",
  darkcyan: "#008b8b",
  darkgoldenrod: "#b8860b",
  darkgray: "#a9a9a9",
  darkgreen: "#006400",
  darkgrey: "#a9a9a9",
  darkkhaki: "#bdb76b",
  darkmagenta: "#8b008b",
  darkolivegreen: "#556b2f",
  darkorange: "#ff8c00",
  darkorchid: "#9932cc",
  darkred: "#8b0000",
  darksalmon: "#e9967a",
  darkseagreen: "#8fbc8f",
  darkslateblue: "#483d8b",
  darkslategray: "#2f4f4f",
  darkslategrey: "#2f4f4f",
  darkturquoise: "#00ced1",
  darkviolet: "#9400d3",
  deeppink: "#ff1493",
  deepskyblue: "#00bfff",
  dimgray: "#696969",
  dimgrey: "#696969",
  dodgerblue: "#1e90ff",
  firebrick: "#b22222",
  floralwhite: "#fffaf0",
  forestgreen: "#228b22",
  fuchsia: "#ff00ff",
  gainsboro: "#dcdcdc",
  ghostwhite: "#f8f8ff",
  gold: "#ffd700",
  goldenrod: "#daa520",
  gray: "#808080",
  green: "#008000",
  greenyellow: "#adff2f",
  grey: "#808080",
  honeydew: "#f0fff0",
  hotpink: "#ff69b4",
  indianred: "#cd5c5c",
  indigo: "#4b0082",
  ivory: "#fffff0",
  khaki: "#f0e68c",
  lavender: "#e6e6fa",
  lavenderblush: "#fff0f5",
  lawngreen: "#7cfc00",
  lemonchiffon: "#fffacd",
  lightblue: "#add8e6",
  lightcoral: "#f08080",
  lightcyan: "#e0ffff",
  lightgoldenrodyellow: "#fafad2",
  lightgray: "#d3d3d3",
  lightgreen: "#90ee90",
  lightgrey: "#d3d3d3",
  lightpink: "#ffb6c1",
  lightsalmon: "#ffa07a",
  lightseagreen: "#20b2aa",
  lightskyblue: "#87cefa",
  lightslategray: "#778899",
  lightslategrey: "#778899",
  lightsteelblue: "#b0c4de",
  lightyellow: "#ffffe0",
  lime: "#00ff00",
  limegreen: "#32cd32",
  linen: "#faf0e6",
  magenta: "#ff00ff",
  maroon: "#800000",
  mediumaquamarine: "#66cdaa",
  mediumblue: "#0000cd",
  mediumorchid: "#ba55d3",
  mediumpurple: "#9370db",
  mediumseagreen: "#3cb371",
  mediumslateblue: "#7b68ee",
  mediumspringgreen: "#00fa9a",
  mediumturquoise: "#48d1cc",
  mediumvioletred: "#c71585",
  midnightblue: "#191970",
  mintcream: "#f5fffa",
  mistyrose: "#ffe4e1",
  moccasin: "#ffe4b5",
  navajowhite: "#ffdead",
  navy: "#000080",
  oldlace: "#fdf5e6",
  olive: "#808000",
  olivedrab: "#6b8e23",
  orange: "#ffa500",
  orangered: "#ff4500",
  orchid: "#da70d6",
  palegoldenrod: "#eee8aa",
  palegreen: "#98fb98",
  paleturquoise: "#afeeee",
  palevioletred: "#db7093",
  papayawhip: "#ffefd5",
  peachpuff: "#ffdab9",
  peru: "#cd853f",
  pink: "#ffc0cb",
  plum: "#dda0dd",
  powderblue: "#b0e0e6",
  purple: "#800080",
  rebeccapurple: "#663399",
  red: "#ff0000",
  rosybrown: "#bc8f8f",
  royalblue: "#4169e1",
  saddlebrown: "#8b4513",
  salmon: "#fa8072",
  sandybrown: "#f4a460",
  seagreen: "#2e8b57",
  seashell: "#fff5ee",
  sienna: "#a0522d",
  silver: "#c0c0c0",
  skyblue: "#87ceeb",
  slateblue: "#6a5acd",
  slategray: "#708090",
  slategrey: "#708090",
  snow: "#fffafa",
  springgreen: "#00ff7f",
  steelblue: "#4682b4",
  tan: "#d2b48c",
  teal: "#008080",
  thistle: "#d8bfd8",
  tomato: "#ff6347",
  turquoise: "#40e0d0",
  violet: "#ee82ee",
  wheat: "#f5deb3",
  white: "#ffffff",
  whitesmoke: "#f5f5f5",
  yellow: "#ffff00",
  yellowgreen: "#9acd32",
  transparent: "#00000000",
};

function parseColor(value: string): Rgba {
  const v = value.trim().toLowerCase();
  const named = NAMED_COLORS[v];
  if (named) return parseColor(named);

  const hex = v.match(/^#([0-9a-f]{3,8})$/);
  if (hex) {
    const h = hex[1] as string;
    if (h.length === 3 || h.length === 4) {
      const [r, g, b, a] = [...h].map((c) => Number.parseInt(c + c, 16));
      return {
        r: r as number,
        g: g as number,
        b: b as number,
        a: (a ?? 255) / 255,
      };
    }
    if (h.length === 6 || h.length === 8) {
      const r = Number.parseInt(h.slice(0, 2), 16);
      const g = Number.parseInt(h.slice(2, 4), 16);
      const b = Number.parseInt(h.slice(4, 6), 16);
      const a = h.length === 8 ? Number.parseInt(h.slice(6, 8), 16) / 255 : 1;
      return { r, g, b, a };
    }
    throw new Error(`invalid hex color length: #${h}`);
  }

  // CSS Color: rgb()/rgba() and hsl()/hsla() have a legacy comma form
  // and a modern whitespace form. We accept both, but they MUST be
  // internally consistent — mixed delimiters (`hsl(32, 100% 50%)`) used
  // to slip through a `[, ]` class on each separator and silently parse.
  // Per CSS Color 4: rgb() channels accept either 0..255 numbers (clamped)
  // OR 0..100% percentages (also clamped). Negative values clamp to 0,
  // values over the max clamp down — matching hsl()/hwb() behaviour so
  // the same out-of-range mistake doesn't produce two different error
  // modes across functional notations.
  const RGB_CHANNEL = "-?[\\d.]+%?";
  const rgbLegacy = v.match(
    new RegExp(
      `^rgba?\\(\\s*(${RGB_CHANNEL})\\s*,\\s*(${RGB_CHANNEL})\\s*,\\s*(${RGB_CHANNEL})\\s*(?:,\\s*([\\d.]+%?)\\s*)?\\)$`,
    ),
  );
  const rgbModern = v.match(
    new RegExp(
      `^rgba?\\(\\s*(${RGB_CHANNEL})\\s+(${RGB_CHANNEL})\\s+(${RGB_CHANNEL})\\s*(?:/\\s*([\\d.]+%?)\\s*)?\\)$`,
    ),
  );
  const rgb = rgbLegacy ?? rgbModern;
  if (rgb) {
    const channel = (s: string): number => {
      const trimmed = s.endsWith("%")
        ? (Number(s.slice(0, -1)) / 100) * 255
        : Number(s);
      // Clamp to [0, 255] and round to the nearest integer byte.
      const clamped = Math.max(0, Math.min(255, trimmed));
      return Math.round(clamped);
    };
    return {
      r: channel(rgb[1] as string),
      g: channel(rgb[2] as string),
      b: channel(rgb[3] as string),
      a: parseAlpha(rgb[4]),
    };
  }

  const hslLegacy = v.match(
    /^hsla?\(\s*(-?[\d.]+)(?:deg)?\s*,\s*([\d.]+)%\s*,\s*([\d.]+)%\s*(?:,\s*([\d.]+%?)\s*)?\)$/,
  );
  const hslModern = v.match(
    /^hsla?\(\s*(-?[\d.]+)(?:deg)?\s+([\d.]+)%\s+([\d.]+)%\s*(?:\/\s*([\d.]+%?)\s*)?\)$/,
  );
  const hsl = hslLegacy ?? hslModern;
  if (hsl) {
    const h = Number(hsl[1]);
    // CSS Color 4 clamps saturation and lightness to [0,100%] at parse time.
    const s = clamp01(Number(hsl[2]) / 100);
    const l = clamp01(Number(hsl[3]) / 100);
    return { ...hslToRgb(h, s, l), a: parseAlpha(hsl[4]) };
  }

  const hwb = v.match(
    /^hwb\(\s*(-?[\d.]+)(?:deg)?\s+([\d.]+)%\s+([\d.]+)%\s*(?:\/\s*([\d.]+%?)\s*)?\)$/,
  );
  if (hwb) {
    const h = Number(hwb[1]);
    const w = clamp01(Number(hwb[2]) / 100);
    const bl = clamp01(Number(hwb[3]) / 100);
    return { ...hwbToRgb(h, w, bl), a: parseAlpha(hwb[4]) };
  }

  // Detect the common "mixed delimiters" mistake explicitly so callers
  // get a useful pointer rather than the generic "cannot parse" message.
  if (
    /^(rgba?|hsla?)\(/.test(v) &&
    /[, ]/.test(v) &&
    /\s,|,\s,\s|, .+ /.test(v)
  ) {
    throw new Error(
      `cannot parse color ${JSON.stringify(value)}: rgb()/hsl() accept commas OR whitespace as separators, not both — pick one form`,
    );
  }

  throw new Error(
    `cannot parse color ${JSON.stringify(value)}: expected #hex, rgb()/rgba(), hsl()/hsla(), hwb(), or a CSS named color`,
  );
}

function clamp01(n: number): number {
  if (Number.isNaN(n)) return 0;
  if (n < 0) return 0;
  if (n > 1) return 1;
  return n;
}

function parseAlpha(raw: string | undefined): number {
  if (raw === undefined) return 1;
  const n = raw.endsWith("%") ? Number(raw.slice(0, -1)) / 100 : Number(raw);
  return clamp01(n);
}

function hslToRgb(
  h: number,
  s: number,
  l: number,
): { r: number; g: number; b: number } {
  const hue = ((h % 360) + 360) % 360;
  const c = (1 - Math.abs(2 * l - 1)) * s;
  const x = c * (1 - Math.abs(((hue / 60) % 2) - 1));
  const m = l - c / 2;
  let [r, g, b] = [0, 0, 0];
  if (hue < 60) [r, g, b] = [c, x, 0];
  else if (hue < 120) [r, g, b] = [x, c, 0];
  else if (hue < 180) [r, g, b] = [0, c, x];
  else if (hue < 240) [r, g, b] = [0, x, c];
  else if (hue < 300) [r, g, b] = [x, 0, c];
  else [r, g, b] = [c, 0, x];
  return {
    r: Math.round((r + m) * 255),
    g: Math.round((g + m) * 255),
    b: Math.round((b + m) * 255),
  };
}

function rgbToHsl(
  r: number,
  g: number,
  b: number,
): { h: number; s: number; l: number } {
  const rn = r / 255;
  const gn = g / 255;
  const bn = b / 255;
  const max = Math.max(rn, gn, bn);
  const min = Math.min(rn, gn, bn);
  const l = (max + min) / 2;
  if (max === min) return { h: 0, s: 0, l };
  const d = max - min;
  const s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
  let h: number;
  if (max === rn) h = ((gn - bn) / d + (gn < bn ? 6 : 0)) * 60;
  else if (max === gn) h = ((bn - rn) / d + 2) * 60;
  else h = ((rn - gn) / d + 4) * 60;
  return { h, s, l };
}

function rgbToHwb(
  r: number,
  g: number,
  b: number,
): { h: number; w: number; bl: number } {
  const { h } = rgbToHsl(r, g, b);
  const w = Math.min(r, g, b) / 255;
  const bl = 1 - Math.max(r, g, b) / 255;
  return { h, w, bl };
}

function hwbToRgb(
  h: number,
  w: number,
  bl: number,
): { r: number; g: number; b: number } {
  // CSS Color 4 §6.4: if w + bl >= 1, the colour collapses to a gray.
  if (w + bl >= 1) {
    const gray = Math.round((w / (w + bl)) * 255);
    return { r: gray, g: gray, b: gray };
  }
  const { r, g, b } = hslToRgb(h, 1, 0.5);
  const mix = (c: number) => Math.round(((c / 255) * (1 - w - bl) + w) * 255);
  return { r: mix(r), g: mix(g), b: mix(b) };
}

/** WCAG relative luminance. */
function luminance(r: number, g: number, b: number): number {
  const channel = (c: number) => {
    const cn = c / 255;
    return cn <= 0.03928 ? cn / 12.92 : ((cn + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

function contrastRatio(l1: number, l2: number): number {
  const [light, dark] = l1 >= l2 ? [l1, l2] : [l2, l1];
  return (light + 0.05) / (dark + 0.05);
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

// WCAG 2.1 contrast thresholds (https://www.w3.org/TR/WCAG21/#contrast-minimum)
// AA / AAA for body text and for "large text" (≥18pt or ≥14pt bold).
function wcagPasses(ratio: number): Record<string, boolean> {
  return {
    aaNormal: ratio >= 4.5,
    aaLarge: ratio >= 3,
    aaaNormal: ratio >= 7,
    aaaLarge: ratio >= 4.5,
  };
}

export interface ColorDescription {
  input: string;
  hex: string;
  rgb: string;
  hsl: string;
  hwb: string;
  alpha: number;
  luminance: number;
  contrastVsWhite: number;
  contrastVsBlack: number;
  wcagVsWhite: Record<string, boolean>;
  wcagVsBlack: Record<string, boolean>;
}

export function describeColor(input: string): ColorDescription {
  const { r, g, b, a } = parseColor(input);
  const { h, s, l } = rgbToHsl(r, g, b);
  const hwb = rgbToHwb(r, g, b);
  const lum = luminance(r, g, b);
  const hexBody = [r, g, b]
    .map((c) => c.toString(16).padStart(2, "0"))
    .join("");
  const alphaHex =
    a < 1
      ? Math.round(a * 255)
          .toString(16)
          .padStart(2, "0")
      : "";
  // Luminance rounded to 4 decimal places — enough fidelity for WCAG
  // contrast computation without floating-point noise in display.
  const lumRounded = Math.round(lum * 10000) / 10000;
  const contrastWhite = round2(contrastRatio(lum, 1));
  const contrastBlack = round2(contrastRatio(lum, 0));
  return {
    input,
    hex: `#${hexBody}${alphaHex}`,
    rgb:
      a < 1 ? `rgba(${r}, ${g}, ${b}, ${round2(a)})` : `rgb(${r}, ${g}, ${b})`,
    hsl:
      a < 1
        ? `hsla(${round2(h)}, ${round2(s * 100)}%, ${round2(l * 100)}%, ${round2(a)})`
        : `hsl(${round2(h)}, ${round2(s * 100)}%, ${round2(l * 100)}%)`,
    hwb: `hwb(${round2(hwb.h)} ${round2(hwb.w * 100)}% ${round2(hwb.bl * 100)}%)`,
    alpha: a,
    luminance: lumRounded,
    contrastVsWhite: contrastWhite,
    contrastVsBlack: contrastBlack,
    wcagVsWhite: wcagPasses(contrastWhite),
    wcagVsBlack: wcagPasses(contrastBlack),
  };
}

export interface ContrastDescription {
  a: string;
  b: string;
  luminanceA: number;
  luminanceB: number;
  contrast: number;
  wcag: Record<string, boolean>;
}

// Pairwise contrast between two colours plus the WCAG bands. Surfaces both
// luminances so the caller doesn't have to pre-decide which is foreground.
export function describeContrast(a: string, b: string): ContrastDescription {
  const ca = parseColor(a);
  const cb = parseColor(b);
  const la = luminance(ca.r, ca.g, ca.b);
  const lb = luminance(cb.r, cb.g, cb.b);
  const ratio = round2(contrastRatio(la, lb));
  return {
    a,
    b,
    luminanceA: Math.round(la * 10000) / 10000,
    luminanceB: Math.round(lb * 10000) / 10000,
    contrast: ratio,
    wcag: wcagPasses(ratio),
  };
}
