// The lock explainer, shown ONCE per device, immediately after the first successful
// login and before Home. It exists because the padlock in the header is otherwise
// unexplained: the wallet is unlocked now, it will lock itself later, and the user
// needs to know that the later signature popup is normal rather than a fresh login.
//
// Three lines, one CTA, no mechanics: "signing key", not "BabyJubJub private key";
// what the padlock does, not what keyCache.ts does. The seen-flag lives in
// lib/lockIntro.ts (a boolean, never key material).

import type { ReactNode } from "react";
import { IconUnlock } from "../components/icons.js";
import { Button } from "../components/controls.js";

export function LockIntro({ onDone }: { onDone: () => void }): ReactNode {
  return (
    <div className="px-5.5 py-6.5 flex flex-col justify-center gap-5 flex-1 bg-bg">
      <div className="flex flex-col items-center gap-3 text-center">
        <span className="inline-flex text-pos">
          <IconUnlock size={52} />
        </span>
        {/* The title says what the screen is about; the first line below says what
            just happened — repeating "unlocked" in both would waste the heading. */}
        <h1 className="text-[1.4rem] font-bold tracking-[-0.01em]">How the lock works</h1>
      </div>

      <ul className="list-none flex flex-col gap-3 p-3.5 bg-surface border border-border rounded-xl text-[0.9rem] text-muted">
        <li>
          You&apos;re ready to send. The key that moves your money only exists while this page
          is open. It is never saved anywhere.
        </li>
        <li>
          If you do nothing for 10 minutes, the wallet locks itself. The padlock at the top
          closes.
        </li>
        <li>
          To send again after that, just confirm once in your wallet app. Your balance is
          always visible, locked or not.
        </li>
      </ul>

      <Button variant="primary" size="lg" block onClick={onDone}>
        Got it
      </Button>
    </div>
  );
}
