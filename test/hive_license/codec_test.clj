(ns hive-license.codec-test
  (:require [clojure.test :refer [deftest is testing]]
            [hive-schemas.test :as st]
            [hive-license.codec :as codec]
            [hive-license.schema :as schema]
            [clojure.string :as str]))

(st/deftrifecta-from-schema canonical-string
  hive-license.codec/canonical-string
  {:in schema/License
   :out [:string {:min 1}]
   :rel (fn [_in out] (pos? (count out)))
   :mutation false
   :num-tests 60})

(deftest canonical-form-is-key-order-independent
  (testing "the same licence written in any key order yields the same bytes"
    (let [a {:license/id "x" :license/customer-id "c"
             :license/entitles #{"g:a" "g:b"}
             :license/node-id nil
             :license/issued-at "2026-01-01T00:00:00Z"
             :license/expires-at "2026-02-01T00:00:00Z"
             :license/key-id "k"}
          b (into {} (reverse (seq a)))]
      (is (= (codec/canonical-string a) (codec/canonical-string b)))
      (is (= (seq (codec/canonical-bytes a)) (seq (codec/canonical-bytes b)))))))

(deftest canonical-form-is-set-order-independent
  (testing "set element order cannot change the signed bytes"
    (let [base {:license/id "x" :license/customer-id "c"
                :license/node-id nil
                :license/issued-at "2026-01-01T00:00:00Z"
                :license/expires-at "2026-02-01T00:00:00Z"
                :license/key-id "k"}]
      (is (= (codec/canonical-string (assoc base :license/entitles #{"g:a" "g:b"}))
             (codec/canonical-string (assoc base :license/entitles #{"g:b" "g:a"})))))))

(deftest canonical-form-separates-distinct-licences
  (testing "a changed field changes the bytes"
    (let [a {:license/id "x" :license/customer-id "c"
             :license/entitles :all :license/node-id nil
             :license/issued-at "2026-01-01T00:00:00Z"
             :license/expires-at "2026-02-01T00:00:00Z"
             :license/key-id "k"}]
      (is (not= (codec/canonical-string a)
                (codec/canonical-string (assoc a :license/customer-id "d")))))))

(deftest base64-round-trips
  (let [bs (byte-array (map byte [1 2 3 -4 -5 127]))]
    (is (= (seq bs) (seq (codec/decode64 (codec/encode64 bs)))))))

(deftest base64-rejects-garbage-without-throwing
  (is (nil? (codec/decode64 "not base64 !!!")))
  (is (nil? (codec/decode64 ""))))

(def ^:private a-licence
  {:license/id "x"
   :license/customer-id "c"
   :license/entitles #{"g:a" "g:b"}
   :license/node-id nil
   :license/issued-at "2026-01-01T00:00:00Z"
   :license/expires-at "2026-02-01T00:00:00Z"
   :license/key-id "k"})

(deftest the-canonical-form-does-not-depend-on-the-callers-printer-settings
  (testing "a licence has namespaced keys, so *print-namespace-maps* alone
            rewrites it — and the signature is computed over these bytes.
            A REPL binds that var to true and a worker thread does not, so a
            licence issued in one and verified in the other would not verify,
            and a constant sealed in one could never be unsealed in the other."
    (let [pinned (codec/canonical-string a-licence)]
      (doseq [nsm [true false]
              readably [true false]
              length [nil 2]
              level [nil 1]]
        (binding [*print-namespace-maps* nsm
                  *print-readably* readably
                  *print-length* length
                  *print-level* level]
          (is (= pinned (codec/canonical-string a-licence))
              (str "printer settings changed the bytes a signature covers: "
               {:namespace-maps nsm :readably readably
                :length length :level level})))))))

(deftest the-canonical-form-is-not-truncated-by-a-print-limit
  (testing "*print-length* would silently drop entitlements from the bytes"
    (let [wide (assoc a-licence :license/entitles
                      (into #{} (map #(str "g:a" %)) (range 50)))
          pinned (codec/canonical-string wide)]
      (binding [*print-length* 3 *print-level* 1]
        (is (= pinned (codec/canonical-string wide))))
      (is (not (clojure.string/includes? pinned "..."))))))
