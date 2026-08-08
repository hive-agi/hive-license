(ns hive-license.crypto
  "Ed25519 primitives over raw bytes, from the JDK provider (Java 15+).

   Keys cross this boundary as X.509 (public) and PKCS#8 (private) encodings,
   which is what KeyFactory consumes and what a keyring stores."
  (:require [hive-license.codec :as codec]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def ^:private algorithm "Ed25519")

(defn generate-keypair
  "Fresh Ed25519 keypair as {:public base64 :private base64}."
  []
  (let [kp (.generateKeyPair (java.security.KeyPairGenerator/getInstance algorithm))]
    {:public (codec/encode64 (.getEncoded (.getPublic kp)))
     :private (codec/encode64 (.getEncoded (.getPrivate kp)))}))

(defn- public-key ^java.security.PublicKey [^bytes x509]
  (.generatePublic (java.security.KeyFactory/getInstance algorithm)
                   (java.security.spec.X509EncodedKeySpec. x509)))

(defn- private-key ^java.security.PrivateKey [^bytes pkcs8]
  (.generatePrivate (java.security.KeyFactory/getInstance algorithm)
                    (java.security.spec.PKCS8EncodedKeySpec. pkcs8)))

(defn sign
  "Detached signature over `payload`, base64. `private-b64` is PKCS#8."
  ^String [^String private-b64 ^bytes payload]
  (let [sig (java.security.Signature/getInstance algorithm)]
    (.initSign sig (private-key (codec/decode64 private-b64)))
    (.update sig payload)
    (codec/encode64 (.sign sig))))

(defn verify
  "True when `signature-b64` is a valid signature over `payload` for
   `public-b64` (X.509). Any malformed input is a false, never a throw."
  [^String public-b64 ^bytes payload ^String signature-b64]
  (boolean
   (try
     (let [pub (codec/decode64 public-b64)
           sg  (codec/decode64 signature-b64)]
       (when (and pub sg)
         (let [sig (java.security.Signature/getInstance algorithm)]
           (.initVerify sig (public-key pub))
           (.update sig payload)
           (.verify sig sg))))
     (catch Exception _ false))))
