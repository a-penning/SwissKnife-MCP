import { z } from "zod";
import { batchProcess } from "../lib/batch.js";
import { describeColor, describeContrast } from "../lib/color.js";
import { toMessage } from "../lib/errors.js";
import { defineTool, err, ok, singleOrBatch } from "./types.js";

export const colorTool = defineTool({
  name: "color",
  title: "Colour converter & accessibility checker",
  description:
    "Convert any CSS colour to every equivalent form and check whether it meets WCAG contrast requirements. " +
    "\n\n" +
    "Reach for this when you have a colour in one notation and need another (hex ↔ rgb ↔ hsl ↔ hwb ↔ CSS name), " +
    "when you need to know whether a foreground/background pair is readable, or when you want a colour's luminance " +
    "and alpha as numbers you can compare. " +
    "\n\n" +
    "Pass `input` as a single colour, or an array to convert many at once. Set `against` (single-input only) to " +
    "compute the contrast ratio between two colours and the AA/AAA pass/fail flags for both normal and large text.\n" +
    "\n" +
    "Examples:\n" +
    '  { "input": "#ff8800" } → hex/rgb/hsl/hwb forms, alpha, luminance, contrast vs white & black\n' +
    '  { "input": "rebeccapurple", "against": "#fff" } → contrast ratio + WCAG pass/fail\n' +
    '  { "input": ["#f80", "rebeccapurple", "rgb(0 128 255)"] } → batch results',
  inputSchema: {
    input: singleOrBatch.describe(
      "A CSS colour string (e.g. '#ff8800', 'rgb(255 136 0)', 'hsl(32 100% 50%)', 'rebeccapurple') or an array of them.",
    ),
    against: z
      .string()
      .optional()
      .describe(
        "Second colour for a pairwise contrast computation. Only valid when `input` is a single string.",
      ),
  },
  refine: (args, ctx) => {
    if (args.against !== undefined && Array.isArray(args.input)) {
      ctx.addIssue({
        code: "custom",
        message: "`against` is only valid when input is a single string",
        path: ["against"],
      });
    }
  },
  handler: (args) => {
    try {
      if (args.against !== undefined) {
        if (Array.isArray(args.input)) {
          return err("`against` is only valid when input is a single string");
        }
        const structured = describeContrast(args.input, args.against);
        return ok(JSON.stringify(structured, null, 2), { ...structured });
      }
      if (Array.isArray(args.input)) {
        const { results, failures } = batchProcess(args.input, describeColor);
        return ok(JSON.stringify({ results, failures }, null, 2), {
          results,
          failures,
        });
      }
      const structured = describeColor(args.input);
      return ok(JSON.stringify(structured, null, 2), { ...structured });
    } catch (e) {
      return err(toMessage(e));
    }
  },
});
