(ns hive-license.gate-test
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [hive-license.core :as lic]
            [hive-license.crypto :as crypto]
            [hive-license.gate :as gate]
            [hive-license.keyring :as keyring]))

(def ^:private kp (crypto/generate-keypair))

(def ^:private license
  {:license/id "lic-1"
   :license/customer-id "acme"
   :license/entitles #{"io.github.hive-agi:hive-carto"}
   :license/node-id nil
   :license/issued-at "2026-01-01T00:00:00Z"
   :license/expires-at "2026-09-01T00:00:00Z"
   :license/key-id "k-gate"})

(def ^:private signed (lic/issue (:private kp) license))

(def ^:private carto-spec
  {:addon/id "hive.carto"
   :addon/trust-class :proprietary
   :addon/entitlement "io.github.hive-agi:hive-carto"})

(def ^:private shape-spec
  (assoc carto-spec :addon/entitlement "io.github.hive-agi:hive-shape"))

(defn- with-key [f]
  (keyring/register! "k-gate" (:public kp))
  (f)
  (keyring/deregister! "k-gate"))

(use-fixtures :each with-key)

(defn- at [now]
  (gate/gate {:signed signed :now-fn (constantly now)}))

(deftest an-entitled-addon-is-permitted
  (is (nil? ((at "2026-06-01T00:00:00Z") carto-spec))))

(deftest an-unentitled-addon-is-refused
  (is (= :deny/entitlement-missing ((at "2026-06-01T00:00:00Z") shape-spec))))

(deftest an-expired-licence-refuses
  (is (= :deny/expired ((at "2027-01-01T00:00:00Z") carto-spec))))

(deftest a-missing-licence-refuses
  (is (= :deny/malformed ((gate/gate {:signed nil}) carto-spec))))

(deftest an-unreadable-licence-source-refuses
  (testing "a throwing source must not mount the addon by accident"
    (let [g (gate/gate {:signed (fn [] (throw (ex-info "no licence file" {})))})]
      (is (= :deny/malformed (g carto-spec))))))

(deftest the-licence-source-is-re-read-per-call
  (testing "a renewal takes effect without a restart"
    (let [current (atom (lic/issue (:private kp)
                                   (assoc license :license/expires-at "2026-02-01T00:00:00Z")))
          g       (gate/gate {:signed #(deref current)
                              :now-fn (constantly "2026-06-01T00:00:00Z")})]
      (is (= :deny/expired (g carto-spec)))
      (reset! current signed)
      (is (nil? (g carto-spec))))))

(deftest node-locking-is-enforced-through-the-gate
  (let [locked (lic/issue (:private kp) (assoc license :license/node-id "node-a"))]
    (is (nil? ((gate/gate {:signed locked
                           :now-fn (constantly "2026-06-01T00:00:00Z")
                           :node-id "node-a"}) carto-spec)))
    (is (= :deny/node-mismatch
           ((gate/gate {:signed locked
                        :now-fn (constantly "2026-06-01T00:00:00Z")
                        :node-id "node-b"}) carto-spec)))))

(deftest the-unit-accessor-is-injectable
  (testing "a host may key entitlement off something other than :addon/entitlement"
    (let [g (gate/gate {:signed signed
                        :now-fn (constantly "2026-06-01T00:00:00Z")
                        :unit-fn (constantly "io.github.hive-agi:hive-carto")})]
      (is (nil? (g {:addon/id "anything"}))))))

(deftest now-iso-parses-as-an-instant
  (is (some? (java.time.Instant/parse (gate/now-iso)))))
