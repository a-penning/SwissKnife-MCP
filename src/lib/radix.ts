const DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz";

export function convertRadix(value: string, from: number, to: number): string {
  let input = value.trim().toLowerCase();
  let negative = false;
  if (input.startsWith("-")) {
    negative = true;
    input = input.slice(1);
  }
  if (input.length === 0) {
    throw new Error("empty number");
  }
  const fromBig = BigInt(from);
  let acc = 0n;
  for (let i = 0; i < input.length; i++) {
    const digit = DIGITS.indexOf(input[i] as string);
    if (digit === -1 || digit >= from) {
      throw new Error(
        `invalid digit ${JSON.stringify(value.trim()[negative ? i + 1 : i])} for base ${from} at offset ${negative ? i + 1 : i}`,
      );
    }
    acc = acc * fromBig + BigInt(digit);
  }
  const toBig = BigInt(to);
  if (acc === 0n) {
    return "0";
  }
  let out = "";
  while (acc > 0n) {
    out = DIGITS[Number(acc % toBig)] + out;
    acc /= toBig;
  }
  return negative ? `-${out}` : out;
}
