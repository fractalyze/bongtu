// Gate for the Sign out coupling (lib/signOut.ts): ending the SERVICE session
// must ALSO lock the key cache — otherwise a spending key would stay warm in
// memory behind the login page after the operator walked away.

import { test, afterEach } from "node:test";
import assert from "node:assert/strict";

import { deriveKeypair } from "@bongtu/core/note";
import { packPubkey } from "@bongtu/core/pubkey";
import type { WalletIdentity } from "@bongtu/client/derive";
import { keyCache } from "../src/lib/keyCache.js";
import { serviceAuth } from "../src/lib/serviceAuth.js";
import { signOutOfService } from "../src/lib/signOut.js";

afterEach(() => {
  serviceAuth.drop();
  keyCache.lock();
});

test("sign-out ends the service session AND locks the key cache", () => {
  const keypair = deriveKeypair(8123456789n);
  const pubkey = packPubkey(keypair.publicKey);
  const identity = { keypair, compressedPubkey: pubkey } as WalletIdentity;
  keyCache.seed(identity, "0xEmployerAccount", pubkey);
  serviceAuth.set("Basic dGhyb3ctaWQ6YXdheS1wdw==");
  assert.equal(keyCache.isUnlocked(), true, "precondition: a held spending key");
  assert.notEqual(serviceAuth.header(), null, "precondition: a live service session");

  signOutOfService();

  assert.equal(serviceAuth.header(), null, "the service session is gone -> login page");
  assert.equal(keyCache.isUnlocked(), false, "the spending key is wiped with it");
});
