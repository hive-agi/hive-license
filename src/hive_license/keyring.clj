(ns hive-license.keyring
  "Key-id -> public key registry. The DIP swap point for signing-key rotation:
   a verifier gains a new key by registering data, never by changing code."
  (:require [hive-license.schema :as schema]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(defonce ^:private registry (atom {}))

(defn register!
  "Register X.509 base64 `public-b64` under `key-id`. Idempotent by key-id."
  [key-id public-b64]
  (schema/check! schema/KeyId key-id {:key-id key-id})
  (schema/check! schema/Base64 public-b64 {:key-id key-id})
  (swap! registry assoc key-id public-b64)
  key-id)

(defn public-key
  "Registered key for `key-id`, or nil."
  [key-id]
  (get @registry key-id))

(defn key-ids
  "Every registered key-id."
  []
  (set (keys @registry)))

(defn deregister!
  "Drop `key-id`."
  [key-id]
  (swap! registry dissoc key-id)
  key-id)
