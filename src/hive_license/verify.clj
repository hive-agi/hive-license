(ns hive-license.verify
  "Licence validity as an ordered rule chain. Pure.

   A rule returns nil to pass, or a DenyReason keyword to stop the chain.
   Extending the policy = registering another rule; `decide` never changes."
  (:require [malli.core :as m]
            [hive-license.codec :as codec]
            [hive-license.crypto :as crypto]
            [hive-license.schema :as schema]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(defprotocol ILicenseRule
  (rule-id [this] "Keyword identifying this rule.")
  (check [this request] "nil to pass, else a DenyReason keyword."))

(defn- instant ^java.time.Instant [s]
  (try (java.time.Instant/parse s) (catch Exception _ nil)))

(def ^:private well-formed
  (reify ILicenseRule
    (rule-id [_] :well-formed)
    (check [_ {:request/keys [signed]}]
      (when-not (m/validate schema/SignedLicense signed)
        :deny/malformed))))

(def ^:private key-known
  (reify ILicenseRule
    (rule-id [_] :key-known)
    (check [_ {:request/keys [public-key]}]
      (when (nil? public-key) :deny/key-unknown))))

(def ^:private signature-valid
  (reify ILicenseRule
    (rule-id [_] :signature-valid)
    (check [_ {:request/keys [signed public-key]}]
      (let [{:signed/keys [license signature]} signed]
        (when-not (crypto/verify public-key (codec/canonical-bytes license) signature)
          :deny/signature-invalid)))))

(def ^:private not-before
  (reify ILicenseRule
    (rule-id [_] :not-before)
    (check [_ {:request/keys [signed now]}]
      (let [issued (instant (get-in signed [:signed/license :license/issued-at]))
            at     (instant now)]
        (when (and issued at (.isBefore at issued))
          :deny/not-yet-valid)))))

(def ^:private not-expired
  (reify ILicenseRule
    (rule-id [_] :not-expired)
    (check [_ {:request/keys [signed now]}]
      (let [expires (instant (get-in signed [:signed/license :license/expires-at]))
            at      (instant now)]
        (when (and expires at (not (.isBefore at expires)))
          :deny/expired)))))

(def ^:private node-matches
  (reify ILicenseRule
    (rule-id [_] :node-matches)
    (check [_ {:request/keys [signed node-id]}]
      (let [locked (get-in signed [:signed/license :license/node-id])]
        (when (and (some? locked) (not= locked node-id))
          :deny/node-mismatch)))))

(def ^:private entitled
  (reify ILicenseRule
    (rule-id [_] :entitled)
    (check [_ {:request/keys [signed unit]}]
      (let [entitles (get-in signed [:signed/license :license/entitles])]
        (when (and (some? unit)
                   (not= :all entitles)
                   (not (contains? (set entitles) unit)))
          :deny/entitlement-missing)))))

(def default-rules
  "Order is the contract: a malformed licence must not reach signature
   checking, and an unverified licence must not reach entitlement checking."
  [well-formed key-known signature-valid not-before not-expired
   node-matches entitled])

(defn decide
  "First denial in `rules`, or a valid verdict."
  ([request] (decide default-rules request))
  ([rules request]
   (if-let [reason (some #(check % request) rules)]
     {:license/valid? false :license/reason reason}
     {:license/valid? true
      :license/license (:signed/license (:request/signed request))})))
