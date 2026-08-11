(ns hive-license.signer
  "Binds licence signing and verification to the ISigner port.

   The default implementation is this library's own JDK adapter, so a shipped
   artifact keeps verifying with no crypto dependency on the classpath. A host
   that already carries a crypto stack may install its own; both speak the same
   base64 PKCS#8/X.509 encodings and produce byte-identical signatures, so the
   two are interchangeable over the same key files.

   `verify` is total by contract — a foreign signer that throws still yields
   false here, because a verdict of \"invalid\" is the only safe reading of a
   signature that could not be checked."
  (:require [hive-license.crypto :as crypto]
            [hive-spi.crypto.ports :as ports]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(defrecord JdkSigner []
  ports/ISigner
  (sign-detached [_ private-b64 payload]
    (crypto/sign private-b64 payload))
  (verify-detached [_ public-b64 payload signature-b64]
    (crypto/verify public-b64 payload signature-b64))
  (signer-algorithm [_] :ed25519))

(def jdk-signer
  "The JDK-provider signer this library ships with."
  (->JdkSigner))

(defn active
  "The installed signer, or the JDK one this library ships with."
  []
  (or (ports/get-signer) jdk-signer))

(defn sign
  "Base64 detached signature over PAYLOAD bytes, under base64 PKCS#8
   PRIVATE-B64."
  [private-b64 payload]
  (ports/sign-detached (active) private-b64 payload))

(defn verify
  "True when SIGNATURE-B64 is a valid signature over PAYLOAD bytes for base64
   X.509 PUBLIC-B64. Never throws."
  [public-b64 payload signature-b64]
  (boolean
   (try
     (ports/verify-detached (active) public-b64 payload signature-b64)
     (catch Exception _ false))))
