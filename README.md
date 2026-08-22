# hive-license

<!-- hive-badges -->

[![Clojars Project](https://img.shields.io/clojars/v/io.github.hive-agi/hive-license.svg)](https://clojars.org/io.github.hive-agi/hive-license)
[![cljdoc](https://cljdoc.org/badge/io.github.hive-agi/hive-license)](https://cljdoc.org/d/io.github.hive-agi/hive-license/CURRENT)
[![release](https://github.com/hive-agi/hive-license/actions/workflows/release.yml/badge.svg)](https://github.com/hive-agi/hive-license/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

<!-- /hive-badges -->

Offline, tamper-evident software licensing for JVM Clojure: Ed25519-signed
licences a shipped artifact can verify with **no network call**, plus
license-locked sealing that ships a value as ciphertext only its licensee can
open.

This is the *mechanism* layer. Its security rests entirely on keys it never
contains — the issuer's private key (server-side) and the sealed plaintext
(server-side) — never on the secrecy of this code, which already travels inside
every artifact it gates. That is why it is safe to be open source (Kerckhoffs's
principle), and it is MIT-licensed.

## What it does

- **Issue / verify.** `issue` signs a licence payload with a PKCS#8 Ed25519
  private key (server-side only). `verify/decide` and the `gate` return a
  verdict from a chain of rules — signature validity, not-before, expiry (with
  issuer-signed **offline grace**), and node lock — with no IO. Adding a policy
  is registering another rule; `decide` never changes.
- **Seal / unseal.** `derive/seal` encrypts a value under a key derived from the
  licence signature (`AES-GCM`, deterministic-SIV IV bound to the plaintext), so
  the ciphertext can ship in a public artifact and only a holder of the matching
  licence can `unseal` it. A pirate without the licence has ciphertext they
  cannot open, and patching out the licence check does not help — the value the
  code needs is gated behind `unseal`.
- **Pluggable signer.** Signing and verification go through hive-spi's `ISigner`
  port. The library ships its own JDK adapter (`signer/jdk-signer`), so a gated
  artifact verifies with no extra crypto dependency; a host with its own crypto
  stack may install an interchangeable one over the same key encodings.

## Usage

```clojure
(require '[hive-license.core :as lic]
         '[hive-license.gate :as gate]
         '[hive-license.derive :as derive])

;; server-side: mint a signed licence
(def signed (lic/issue private-b64
                       {:license/id "lic-001"
                        :license/customer-id "acme"
                        :license/entitles #{"io.github.hive-agi:hive-carto"}
                        :license/node-id nil
                        :license/issued-at  "2026-01-01T00:00:00Z"
                        :license/expires-at "2027-01-01T00:00:00Z"
                        :license/offline-grace-seconds 86400
                        :license/key-id "k1"}))

;; in the gated artifact: verify offline, then open the sealed value
((gate/gate {:signed signed}) some-spec)       ; => nil when allowed, :deny/… otherwise
(derive/unseal signed "carto/scoring-weights" ciphertext)  ; => plaintext, or nil
```

## License

MIT — see [LICENSE](LICENSE).
