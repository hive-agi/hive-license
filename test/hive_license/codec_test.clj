(ns hive-license.codec-test
  (:require [clojure.test :refer [deftest is testing]]
            [hive-schemas.test :as st]
            [hive-license.codec :as codec]
            [hive-license.schema :as schema]))

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
