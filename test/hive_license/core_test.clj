(ns hive-license.core-test
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [hive-license.core :as lic]
            [hive-license.crypto :as crypto]
            [hive-license.keyring :as keyring]))

(def ^:private kp (crypto/generate-keypair))

(def ^:private license
  {:license/id "lic-1"
   :license/customer-id "acme"
   :license/entitles #{"io.github.hive-agi:hive-carto"}
   :license/node-id nil
   :license/issued-at "2026-01-01T00:00:00Z"
   :license/expires-at "2026-09-01T00:00:00Z"
   :license/key-id "k-core"})

(defn- with-clean-keyring [f]
  (doseq [id (keyring/key-ids)] (keyring/deregister! id))
  (f)
  (doseq [id (keyring/key-ids)] (keyring/deregister! id)))

(use-fixtures :each with-clean-keyring)

(deftest sign-then-verify-round-trips
  (keyring/register! "k-core" (:public kp))
  (let [signed (lic/issue (:private kp) license)]
    (is (lic/valid? {:signed signed
                     :now "2026-06-01T00:00:00Z"
                     :node-id nil
                     :unit "io.github.hive-agi:hive-carto"}))))

(deftest an-unregistered-key-id-is-unknown
  (testing "verification is offline: an unknown key-id cannot be fetched"
    (let [signed (lic/issue (:private kp) license)]
      (is (= :deny/key-unknown
             (:license/reason (lic/verify {:signed signed
                                           :now "2026-06-01T00:00:00Z"
                                           :node-id nil
                                           :unit nil})))))))

(deftest key-rotation-is-a-registry-entry
  (testing "a second signing key is added as data, with no call-site change"
    (let [kp2 (crypto/generate-keypair)
          l2  (assoc license :license/key-id "k-next")]
      (keyring/register! "k-core" (:public kp))
      (keyring/register! "k-next" (:public kp2))
      (is (lic/valid? {:signed (lic/issue (:private kp) license)
                       :now "2026-06-01T00:00:00Z" :node-id nil :unit nil}))
      (is (lic/valid? {:signed (lic/issue (:private kp2) l2)
                       :now "2026-06-01T00:00:00Z" :node-id nil :unit nil}))
      (testing "and a retired key stops verifying once deregistered"
        (keyring/deregister! "k-core")
        (is (= :deny/key-unknown
               (:license/reason (lic/verify {:signed (lic/issue (:private kp) license)
                                             :now "2026-06-01T00:00:00Z"
                                             :node-id nil :unit nil}))))))))

(deftest a-licence-signed-by-the-wrong-key-for-a-known-id-is-refused
  (testing "registering key A under an id does not let key B sign for it"
    (keyring/register! "k-core" (:public kp))
    (let [impostor (crypto/generate-keypair)]
      (is (= :deny/signature-invalid
             (:license/reason (lic/verify {:signed (lic/issue (:private impostor) license)
                                           :now "2026-06-01T00:00:00Z"
                                           :node-id nil :unit nil})))))))

(deftest issuing-refuses-a-malformed-licence
  (is (thrown? clojure.lang.ExceptionInfo
               (lic/issue (:private kp) (dissoc license :license/customer-id)))))
