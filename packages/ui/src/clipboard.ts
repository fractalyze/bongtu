// Clipboard copy as a boolean-returning edge (the same contract treasury-web's
// lib/clipboard.ts established): browsers reject writeText outside a secure
// context / user gesture, and headless tests have no navigator.clipboard at all.
// The Copy-details affordance (Toast.tsx) claims "Copied" only on a true return.
// Injectable purely so node:test covers both branches without a DOM.

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
