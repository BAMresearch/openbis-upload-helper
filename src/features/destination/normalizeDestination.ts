export function normalizeDestinationCode(
  value: string,
): string {
  return value
    .trim()
    .replace(/\s+/g, "_")
    .toUpperCase();
}