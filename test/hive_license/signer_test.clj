(ns hive-license.signer-test
  "The ISigner seam: which implementation signs, and what the library
   guarantees regardless of which one it is."
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [hive-license.codec :as codec]
            [hive-license.core :as lic]
            [hive-license.crypto :as crypto]
            [hive-license.keyring :as keyring]
            [hive-license.signer :as signer]
            [hive-spi.crypto.ports :as ports]))

(def ^:private kp (crypto/generate-keypair))

(def ^:private license
  {:license/id "lic-1"
   :license/customer-id "acme"
   :license/entitles #{"io.github.hive-agi:hive-carto"}
   :license/node-id "node-1"
   :license/issued-at "2026-01-01T00:00:00Z"
   :license/expires-at "2026-09-01T00:00:00Z"
   :license/key-id "signer-test-key"})

;; The slot is process-wide, so every test restores whatever it found.
(defn- with-clean-slot [f]
  (let [installed (ports/get-signer)]
    (try
      (ports/set-signer! (signer/->JdkSigner))
      (keyring/register! "signer-test-key" (:public kp))
      (f)
      (finally
        (when installed (ports/set-signer! installed))))))

(use-fixtures :each with-clean-slot)

;; A signer that delegates to the JDK one but records that it was asked. Stands
;; in for any host-supplied implementation without naming a real crypto stack.
(defrecord RecordingSigner [calls delegate]
  ports/ISigner
  (sign-detached [_ private-b64 payload]
    (swap! calls conj :sign)
    (ports/sign-detached delegate private-b64 payload))
  (verify-detached [_ public-b64 payload signature-b64]
    (swap! calls conj :verify)
    (ports/verify-detached delegate public-b64 payload signature-b64))
  (signer-algorithm [_] :ed25519))

(defrecord ThrowingSigner []
  ports/ISigner
  (sign-detached [_ _ _] (throw (ex-info "signer is broken" {})))
  (verify-detached [_ _ _ _] (throw (ex-info "signer is broken" {})))
  (signer-algorithm [_] :ed25519))

(deftest the-shipped-default-needs-no-installation
  (testing "with nothing installed, the library signs with its own JDK adapter"
    (ports/clear-signer!)
    (is (instance? hive_license.signer.JdkSigner (signer/active))
        "a shipped artifact must verify with no crypto dependency present")
    (is (= :ed25519 (ports/signer-algorithm (signer/active))))))

(deftest an-installed-signer-takes-over-both-directions
  (let [calls (atom [])]
    (ports/set-signer! (->RecordingSigner calls (signer/->JdkSigner)))
    (let [signed (lic/issue (:private kp) license)]
      (is (:license/valid? (lic/verify {:signed signed
                                        :now "2026-06-01T00:00:00Z"
                                        :node-id "node-1"
                                        :unit "io.github.hive-agi:hive-carto"})))
      (is (= [:sign :verify] @calls)
          "issue and verify both route through the installed signer"))))

(deftest a-swap-does-not-invalidate-existing-licences
  (testing "the encodings are shared, so a licence outlives the implementation"
    (let [before (lic/issue (:private kp) license)
          _      (ports/set-signer! (->RecordingSigner (atom []) (signer/->JdkSigner)))
          after  (lic/issue (:private kp) license)]
      (is (= (:signed/signature before) (:signed/signature after))
          "same key material and payload must yield the same signature")
      (is (:license/valid? (lic/verify {:signed before
                                        :now "2026-06-01T00:00:00Z"
                                        :node-id "node-1"
                                        :unit "io.github.hive-agi:hive-carto"}))))))

(deftest verification-stays-total-when-a-signer-misbehaves
  (testing "an adapter that throws yields an invalid verdict, never an escape"
    (let [signed (lic/issue (:private kp) license)]
      (ports/set-signer! (->ThrowingSigner))
      (is (false? (signer/verify (:public kp) (codec/canonical-bytes license) "AAAA"))
          "a throwing verify is read as invalid")
      (is (= :deny/signature-invalid
             (:license/reason (lic/verify {:signed signed
                                           :now "2026-06-01T00:00:00Z"
                                           :unit "io.github.hive-agi:hive-carto"})))
          "and the verdict is a denial rather than a thrown exception"))))
