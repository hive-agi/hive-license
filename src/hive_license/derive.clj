(ns hive-license.derive
  "Key material derived from a signed licence, and AES-GCM sealing under it.

   Contract: the derived key depends on the signature, which cannot be produced
   without the private key. A caller that needs `unseal` to obtain a value it
   depends on therefore cannot be satisfied by deleting the licence check."
  (:require [hive-license.codec :as codec]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def ^:private gcm-tag-bits 128)
(def ^:private iv-length 12)

(defn- sha256 ^bytes [& parts]
  (let [md (java.security.MessageDigest/getInstance "SHA-256")]
    (doseq [^bytes p parts] (when p (.update md p)))
    (.digest md)))

(defn- utf8 ^bytes [^String s] (.getBytes s "UTF-8"))

(defn derive-key
  "32 key bytes for `purpose`, bound to `signed`'s signature and payload."
  ^bytes [signed ^String purpose]
  (sha256 (utf8 purpose)
          (codec/decode64 (:signed/signature signed))
          (codec/canonical-bytes (:signed/license signed))))

(defn- iv-for ^bytes [^String purpose]
  (java.util.Arrays/copyOf (sha256 (utf8 (str purpose "/iv"))) iv-length))

(defn- cipher [mode ^bytes key-bytes ^String purpose]
  (doto (javax.crypto.Cipher/getInstance "AES/GCM/NoPadding")
    (.init (int mode)
           (javax.crypto.spec.SecretKeySpec. key-bytes "AES")
           (javax.crypto.spec.GCMParameterSpec. gcm-tag-bits (iv-for purpose)))))

(defn seal
  "Base64 ciphertext of `plaintext` under the key derived for `purpose`.
   Deterministic: the IV is derived from `purpose`, so sealing is reproducible."
  ^String [signed ^String purpose ^String plaintext]
  (codec/encode64
   (.doFinal (cipher javax.crypto.Cipher/ENCRYPT_MODE (derive-key signed purpose) purpose)
             (utf8 plaintext))))

(defn unseal
  "Plaintext of base64 `ciphertext`, or nil when the licence does not derive
   the key it was sealed under."
  [signed ^String purpose ^String ciphertext]
  (try
    (String. ^bytes (.doFinal (cipher javax.crypto.Cipher/DECRYPT_MODE
                                      (derive-key signed purpose) purpose)
                              (codec/decode64 ciphertext))
             "UTF-8")
    (catch Exception _ nil)))
