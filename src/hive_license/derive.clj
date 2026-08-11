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

(defn- synthetic-iv
  "12-byte IV bound to the key, purpose and plaintext, so two distinct
   plaintexts never share an IV under one licence (deterministic SIV): a
   (key, IV) reuse across different plaintexts — catastrophic for AES-GCM —
   cannot arise, while identical inputs still seal identically."
  ^bytes [^bytes key-bytes ^String purpose ^bytes plaintext-bytes]
  (java.util.Arrays/copyOf
   (sha256 (utf8 "hive-license/iv/v2") key-bytes (utf8 purpose) plaintext-bytes)
   iv-length))

(defn- cipher [mode ^bytes key-bytes ^bytes iv-bytes]
  (doto (javax.crypto.Cipher/getInstance "AES/GCM/NoPadding")
    (.init (int mode)
           (javax.crypto.spec.SecretKeySpec. key-bytes "AES")
           (javax.crypto.spec.GCMParameterSpec. gcm-tag-bits iv-bytes))))

(defn seal
  "Base64 of (IV ‖ AES-GCM ciphertext) of `plaintext` under the key derived for
   `purpose`. Deterministic: the IV is derived from the key, purpose and
   plaintext, so sealing is reproducible and two distinct plaintexts never share
   an IV under one licence."
  ^String [signed ^String purpose ^String plaintext]
  (let [key-bytes (derive-key signed purpose)
        pt (utf8 plaintext)
        iv (synthetic-iv key-bytes purpose pt)
        ct (.doFinal (cipher javax.crypto.Cipher/ENCRYPT_MODE key-bytes iv) pt)
        out (byte-array (+ iv-length (alength ct)))]
    (System/arraycopy iv 0 out 0 iv-length)
    (System/arraycopy ct 0 out iv-length (alength ct))
    (codec/encode64 out)))

(defn unseal
  "Plaintext of base64 `ciphertext` (IV ‖ AES-GCM ciphertext), or nil when the
   licence does not derive the key it was sealed under, the bytes were altered,
   or the input is malformed."
  [signed ^String purpose ^String ciphertext]
  (try
    (let [raw (codec/decode64 ciphertext)]
      (when (and raw (> (alength ^bytes raw) iv-length))
        (let [iv (java.util.Arrays/copyOfRange ^bytes raw 0 iv-length)
              ct (java.util.Arrays/copyOfRange ^bytes raw iv-length (alength ^bytes raw))]
          (String. ^bytes (.doFinal (cipher javax.crypto.Cipher/DECRYPT_MODE
                                             (derive-key signed purpose) iv)
                                    ct)
                   "UTF-8"))))
    (catch Exception _ nil)))
