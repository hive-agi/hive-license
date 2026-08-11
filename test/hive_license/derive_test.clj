(ns hive-license.derive-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [hive-license.codec :as codec]
            [hive-license.core :as lic]
            [hive-license.crypto :as crypto]
            [hive-license.derive :as derive]))

(def ^:private kp (crypto/generate-keypair))

(def ^:private license
  {:license/id "lic-1"
   :license/customer-id "acme"
   :license/entitles :all
   :license/node-id nil
   :license/issued-at "2026-01-01T00:00:00Z"
   :license/expires-at "2026-09-01T00:00:00Z"
   :license/key-id "k1"})

(def ^:private signed (lic/issue (:private kp) license))
(def ^:private purpose "carto/scoring-weights")
(def ^:private secret "{:alpha 0.62 :beta 0.31}")

(deftest a-derived-key-is-32-bytes
  (is (= 32 (alength (derive/derive-key signed purpose)))))

(deftest purposes-are-separated
  (is (not= (seq (derive/derive-key signed "a"))
            (seq (derive/derive-key signed "b")))))

(deftest sealing-is-deterministic
  (testing "reproducible builds require the same plaintext to seal identically"
    (is (= (derive/seal signed purpose secret)
           (derive/seal signed purpose secret)))))

(deftest the-genuine-licence-unseals
  (is (= secret (derive/unseal signed purpose (derive/seal signed purpose secret)))))

(deftest a-forged-licence-does-not-unseal
  (testing "an attacker signing an identical payload with their own key derives a different key"
    (let [evil (lic/issue (:private (crypto/generate-keypair)) license)]
      (is (nil? (derive/unseal evil purpose (derive/seal signed purpose secret)))))))

(deftest another-customers-licence-does-not-unseal
  (testing "a licence genuinely signed by us, for someone else, is still the wrong key"
    (let [other (lic/issue (:private kp) (assoc license :license/customer-id "other"))]
      (is (nil? (derive/unseal other purpose (derive/seal signed purpose secret)))))))

(deftest the-wrong-purpose-does-not-unseal
  (is (nil? (derive/unseal signed "other/table" (derive/seal signed purpose secret)))))

(deftest a-tampered-ciphertext-does-not-unseal
  (testing "GCM authenticates: a flipped byte is a nil, never a wrong plaintext"
    (let [sealed (derive/seal signed purpose secret)
          broken (str (subs sealed 0 (dec (count sealed)))
                      (if (= \A (last sealed)) "B" "A"))]
      (is (nil? (derive/unseal signed purpose broken))))))

(deftest distinct-plaintexts-never-share-an-iv-under-one-licence
  (testing "the AES-GCM footgun deterministic sealing must avoid: sealing two
            different plaintexts under one (key, IV) breaks both"
    (let [a (derive/seal signed purpose "{:alpha 0.62}")
          b (derive/seal signed purpose "{:alpha 0.63}")
          iv (fn [s] (vec (take 12 (codec/decode64 s))))]
      (is (not= a b) "distinct plaintexts seal to distinct blobs")
      (is (not= (iv a) (iv b))
          "and to distinct IV prefixes, so no keystream is ever reused"))))

(deftest the-sealed-blob-prepends-a-twelve-byte-iv
  (testing "the IV travels with the ciphertext, so unseal needs no shared table"
    (let [blob (derive/seal signed purpose secret)
          raw (codec/decode64 blob)]
      (is (< 12 (alength raw)) "a 12-byte IV prefix plus a non-empty GCM body")
      (is (= secret (derive/unseal signed purpose blob))
          "and the prefixed IV is what unseal reads back"))))

(defspec unseal-inverts-seal-over-arbitrary-plaintext 200
  (prop/for-all [s gen/string]
    (= s (derive/unseal signed purpose (derive/seal signed purpose s)))))
