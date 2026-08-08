(ns hive-license.core
  "Facade: issue a licence, verify one offline.

   Verification performs no IO. The caller supplies the clock and the host
   identity, so the same inputs always yield the same verdict."
  (:require [hive-license.codec :as codec]
            [hive-license.crypto :as crypto]
            [hive-license.keyring :as keyring]
            [hive-license.schema :as schema]
            [hive-license.verify :as verify]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(defn issue
  "Sign `license` with PKCS#8 `private-b64`, returning a SignedLicense.
   Server-side only — no shipped artifact carries a private key."
  [private-b64 license]
  (schema/check! schema/License license {:license-id (:license/id license)})
  {:signed/license license
   :signed/signature (crypto/sign private-b64 (codec/canonical-bytes license))})

(defn request
  "Assemble the VerifyRequest a verdict is computed from. Pure.

   `public-key` is resolved from the keyring by the licence's own key-id, so
   rotation is a registry entry rather than a call-site change."
  [{:keys [signed now node-id unit]}]
  {:request/signed signed
   :request/now now
   :request/node-id node-id
   :request/unit unit
   :request/public-key (some-> (get-in signed [:signed/license :license/key-id])
                               keyring/public-key)})

(defn verify
  "Verdict for `signed` at `now`, on host `node-id`, for entitlement `unit`.

   Returns {:license/valid? true :license/license L} or
           {:license/valid? false :license/reason DenyReason}."
  [opts]
  (verify/decide (request opts)))

(defn valid?
  "True when `opts` yields a valid verdict."
  [opts]
  (:license/valid? (verify opts)))
