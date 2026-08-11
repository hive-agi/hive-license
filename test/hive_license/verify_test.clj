(ns hive-license.verify-test
  (:require [clojure.test :refer [deftest is testing]]
            [hive-schemas.test :as st]
            [hive-license.codec :as codec]
            [hive-license.core :as lic]
            [hive-license.crypto :as crypto]
            [hive-license.schema :as schema]
            [hive-license.verify :as verify]))

(def ^:private kp (crypto/generate-keypair))

(def ^:private license
  {:license/id "lic-1"
   :license/customer-id "acme"
   :license/entitles #{"io.github.hive-agi:hive-carto"}
   :license/node-id "node-1"
   :license/issued-at "2026-01-01T00:00:00Z"
   :license/expires-at "2026-09-01T00:00:00Z"
   :license/key-id "k1"})

(def ^:private signed (lic/issue (:private kp) license))

(defn- req [overrides]
  (merge {:request/signed signed
          :request/now "2026-06-01T00:00:00Z"
          :request/node-id "node-1"
          :request/unit "io.github.hive-agi:hive-carto"
          :request/public-key (:public kp)}
         overrides))

(st/deftrifecta-from-schema decide
  hive-license.verify/decide
  {:in schema/VerifyRequest
   :out schema/Verdict
   :rel (fn [_in out]
          (if (:license/valid? out)
            (some? (:license/license out))
            (some? (:license/reason out))))
   :mutation false
   :num-tests 60})

(deftest the-denial-table
  (testing "each rule denies with its own reason"
    (doseq [[overrides expected]
            [[{:request/signed nil}                :deny/malformed]
             [{:request/public-key nil}            :deny/key-unknown]
             [{:request/signed (assoc-in signed [:signed/license :license/customer-id] "evil")}
              :deny/signature-invalid]
             [{:request/now "2025-01-01T00:00:00Z"} :deny/not-yet-valid]
             [{:request/now "2027-01-01T00:00:00Z"} :deny/expired]
             [{:request/node-id "other"}            :deny/node-mismatch]
             [{:request/unit "io.github.hive-agi:hive-shape"}
              :deny/entitlement-missing]]]
      (is (= expected (:license/reason (verify/decide (req overrides))))
          (pr-str overrides)))))

(deftest a-good-licence-passes-every-rule
  (let [verdict (verify/decide (req {}))]
    (is (:license/valid? verdict))
    (is (= license (:license/license verdict)))
    (is (nil? (:license/reason verdict)))))

(deftest an-unlocked-licence-matches-any-node
  (let [unlocked (lic/issue (:private kp) (assoc license :license/node-id nil))]
    (is (:license/valid? (verify/decide (req {:request/signed unlocked
                                              :request/node-id "anything"}))))))

(deftest all-access-entitles-every-unit
  (let [all (lic/issue (:private kp) (assoc license :license/entitles :all))]
    (is (:license/valid? (verify/decide (req {:request/signed all
                                              :request/unit "io.github.hive-agi:anything"}))))))

(deftest expiry-is-exclusive-at-the-boundary
  (testing "a licence is dead at its expiry instant, not after it"
    (is (= :deny/expired
           (:license/reason (verify/decide (req {:request/now "2026-09-01T00:00:00Z"})))))
    (is (:license/valid?
         (verify/decide (req {:request/now "2026-08-31T23:59:59Z"}))))))

(deftest issuer-signed-offline-grace-extends-the-local-deadline
  (let [graced (lic/issue (:private kp)
                          (assoc license :license/offline-grace-seconds 3600))]
    (testing "the verifier performs no network IO and permits the signed window"
      (is (:license/valid?
           (verify/decide (req {:request/signed graced
                                :request/now "2026-09-01T00:59:59Z"})))))
    (testing "the grace endpoint is exclusive like contractual expiry"
      (is (= :deny/expired
             (:license/reason
              (verify/decide (req {:request/signed graced
                                   :request/now "2026-09-01T01:00:00Z"}))))))))

(deftest offline-grace-is-signature-covered
  (let [graced (lic/issue (:private kp)
                          (assoc license :license/offline-grace-seconds 3600))
        tampered (assoc-in graced
                           [:signed/license :license/offline-grace-seconds]
                           7200)]
    (is (= :deny/signature-invalid
           (:license/reason (verify/decide (req {:request/signed tampered})))))))

(deftest rule-order-is-part-of-the-contract
  (testing "a malformed licence is refused before any signature work"
    (is (= :deny/malformed
           (:license/reason (verify/decide (req {:request/signed {:garbage true}}))))))
  (testing "an unverified licence never reaches entitlement checking"
    (is (= :deny/signature-invalid
           (:license/reason
            (verify/decide (req {:request/signed (assoc-in signed [:signed/license :license/entitles] :all)
                                 :request/unit "io.github.hive-agi:hive-shape"})))))))

(deftest the-chain-is-open-for-extension
  (testing "a new policy is a new rule, not an edit to decide"
    (let [banned (reify verify/ILicenseRule
                   (rule-id [_] :customer-banned)
                   (check [_ r]
                     (when (= "acme" (get-in r [:request/signed :signed/license :license/customer-id]))
                       :deny/entitlement-missing)))
          rules  (conj (vec verify/default-rules) banned)]
      (is (:license/valid? (verify/decide (req {}))))
      (is (false? (:license/valid? (verify/decide rules (req {}))))))))

(deftest signature-covers-every-field
  (testing "mutating any covered field invalidates the signature"
    (let [replacements {:license/id "mutated"
                        :license/customer-id "mutated"
                        :license/entitles :all
                        :license/node-id "mutated-node"
                        :license/issued-at "2026-02-02T00:00:00Z"
                        :license/expires-at "2026-10-01T00:00:00Z"
                        :license/key-id "mutated"}]
      (is (= (set (keys license)) (set (keys replacements)))
          "every licence field needs a schema-valid mutant, or this test is vacuous")
      (doseq [[k v] replacements]
        (let [mutated (assoc-in signed [:signed/license k] v)]
          (is (= :deny/signature-invalid
                 (:license/reason (verify/decide (req {:request/signed mutated}))))
              (str "field not covered by the signature: " k)))))))

(deftest a-signature-from-another-key-is-refused
  (let [other (crypto/generate-keypair)
        forged (lic/issue (:private other) license)]
    (is (= :deny/signature-invalid
           (:license/reason (verify/decide (req {:request/signed forged})))))))

(deftest malformed-signature-bytes-do-not-throw
  (is (= :deny/signature-invalid
         (:license/reason (verify/decide (req {:request/signed (assoc signed :signed/signature "")})))))
  (is (= :deny/signature-invalid
         (:license/reason (verify/decide (req {:request/signed (assoc signed :signed/signature (codec/encode64 (byte-array 8)))}))))))
