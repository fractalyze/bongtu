// Clipboard copy as a boolean-returning edge: browsers reject writeText outside a
// secure context / user gesture, and headless tests have no navigator.clipboard at
// all. Callers get true/false instead of an exception so the UI can show "Copied"
// feedback only when the copy really landed (the full text stays on screen as the
// manual fallback). The clipboard is injectable purely so node:test can cover both
// branches without a DOM.

export interface ClipboardLike {
  writeText(text: string): Promise<void>;
}

export async function copyText(text: string, clip?: ClipboardLike): Promise<boolean> {
  const c =
    clip ?? (typeof navigator !== "undefined" ? (navigator.clipboard as ClipboardLike | undefined) : undefined);
  if (!c) return false;
  try {
    await c.writeText(text);
    return true;
  } catch {
    return false;
  }
}
