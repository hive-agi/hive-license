(ns hive-license.schema
  "Malli value objects for licences.

   Times are ISO-8601 strings, not Date instances: a licence must round-trip
   through bytes unchanged for its signature to verify."
  (:require [malli.core :as m]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def NonBlank [:string {:min 1}])

(defn iso-instant?
  "True when `s` parses as an ISO-8601 instant."
  [s]
  (and (string? s)
       (try (java.time.Instant/parse s) true
            (catch Exception _ false))))

(def IsoInstant
  [:and {:gen/elements ["2026-01-01T00:00:00Z"
                        "2026-06-15T12:30:00Z"
                        "2027-01-01T00:00:00Z"
                        "2030-12-31T23:59:59Z"]}
   :string
   [:fn {:error/message "not an ISO-8601 instant"} iso-instant?]])

(def EntitlementUnit
  "Maven-style entitlement unit, e.g. io.github.hive-agi:hive-carto."
  [:re {:gen/elements ["io.github.hive-agi:hive-carto"
                       "io.github.hive-agi:hive-shape"
                       "io.github.hive-agi:hive-knowledge"]}
   #"^[^:\s]+:[^:\s]+$"])

(def Entitles
  "Units this licence grants, or :all."
  [:or [:= :all] [:set EntitlementUnit]])

(def KeyId
  "Selects the public key a verifier checks the signature against."
  NonBlank)

(def NodeId
  "Opaque host identity the licence is locked to; nil means unlocked."
  [:maybe NonBlank])

(def License
  "The signed payload. Every field is covered by the signature."
  [:map {:closed true}
   [:license/id NonBlank]
   [:license/customer-id NonBlank]
   [:license/entitles Entitles]
   [:license/node-id NodeId]
   [:license/issued-at IsoInstant]
   [:license/expires-at IsoInstant]
   [:license/key-id KeyId]])

(def Base64 [:re {:gen/elements ["aGVsbG8=" "d29ybGQ="]} #"^[A-Za-z0-9+/]*={0,2}$"])

(def SignedLicense
  "A licence plus the detached Ed25519 signature over its canonical bytes."
  [:map {:closed true}
   [:signed/license License]
   [:signed/signature Base64]])

(def DenyReason
  [:enum :deny/malformed :deny/key-unknown :deny/signature-invalid
   :deny/not-yet-valid :deny/expired :deny/node-mismatch
   :deny/entitlement-missing])

(def Verdict
  "Result of verification. :license/key is present only when valid."
  [:map
   [:license/valid? :boolean]
   [:license/reason {:optional true} DenyReason]
   [:license/license {:optional true} License]])

(def VerifyRequest
  "Everything a verdict is computed from. Pure input — the caller supplies the
   clock and the host identity, so verification performs no IO."
  [:map {:closed true}
   [:request/signed [:maybe SignedLicense]]
   [:request/now IsoInstant]
   [:request/node-id NodeId]
   [:request/unit [:maybe EntitlementUnit]]
   [:request/public-key [:maybe Base64]]])

(defn check!
  "Validate `value` against `schema` or throw with `ctx`."
  [schema value ctx]
  (if (m/validate schema value)
    value
    (throw (ex-info "schema violation"
                    (assoc ctx :explain (pr-str (m/explain schema value)))))))
