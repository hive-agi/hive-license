(ns hive-license.gate
  "A licence gate as a plain function of a mount spec.

   Returns nil to permit and a DenyReason keyword to refuse, which is the
   contract hive-addon's mounter consumes. Neither library depends on the
   other: the gate is an ordinary fn, so the coupling is a calling
   convention rather than a classpath edge."
  (:require [hive-license.core :as core]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(defn now-iso
  "This host's clock as an ISO-8601 instant string."
  []
  (str (java.time.Instant/now)))

(defn gate
  "Build (fn [spec] -> nil | DenyReason) from a licence source.

   opts:
     :signed   a SignedLicense, or a 0-arg fn returning one. A fn is read on
               every call, so a renewed licence takes effect without a restart.
     :now-fn   (fn [] -> ISO instant string)      default: this host's clock
     :node-id  this host's identity, or nil       default: nil
     :unit-fn  (fn [spec] -> entitlement unit)    default: :addon/entitlement

   A licence source that throws is a refusal (:deny/malformed), so a missing
   or unreadable licence file cannot mount an addon by accident."
  [{:keys [signed now-fn node-id unit-fn]
    :or {now-fn now-iso unit-fn :addon/entitlement}}]
  (fn [spec]
    (let [current (try (if (fn? signed) (signed) signed)
                       (catch Exception _ ::unreadable))]
      (if (= ::unreadable current)
        :deny/malformed
        (let [verdict (core/verify {:signed current
                                    :now (now-fn)
                                    :node-id node-id
                                    :unit (unit-fn spec)})]
          (when-not (:license/valid? verdict)
            (:license/reason verdict)))))))
