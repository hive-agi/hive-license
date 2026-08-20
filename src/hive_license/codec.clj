(ns hive-license.codec
  "Canonical serialization of a licence.

   Contract: two structurally equal licences produce identical bytes, on any
   host, in any JVM. Signatures are computed over these bytes, so any
   divergence here invalidates every licence in the field."
  (:require [clojure.string :as str]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(defn- canonical
  "Total order on the value shapes a licence may contain."
  [x]
  (cond
    (map? x) (into (sorted-map) (map (fn [[k v]] [(canonical k) (canonical v)])) x)
    (set? x) (vec (sort (map (comp pr-str canonical) x)))
    (vector? x) (mapv canonical x)
    (seq? x) (mapv canonical x)
    :else x))

(defn canonical-string
  "Deterministic textual form of `license`.

   Every printer var the reader-visible form depends on is bound here, so the
   result is a function of the value alone and not of the thread that computed
   it."
  [license]
  (binding [*print-namespace-maps* false
            *print-readably* true
            *print-dup* false
            *print-meta* false
            *print-length* nil
            *print-level* nil]
    (pr-str (canonical license))))

(defn canonical-bytes
  "UTF-8 bytes a signature is computed over."
  ^bytes [license]
  (.getBytes ^String (canonical-string license) "UTF-8"))

(defn encode64
  "Base64 of `bs`."
  ^String [^bytes bs]
  (.encodeToString (java.util.Base64/getEncoder) bs))

(defn decode64
  "Bytes of base64 `s`, or nil when `s` is not valid base64."
  ^bytes [^String s]
  (when-not (str/blank? s)
    (try (.decode (java.util.Base64/getDecoder) s)
         (catch IllegalArgumentException _ nil))))
