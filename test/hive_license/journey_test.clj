(ns hive-license.journey-test
  "The customer journey, driven end to end: a minted key decides which addons a
   host mounts.

   `gate/gate` returns a function and says in its docstring that this is 'the
   contract hive-addon's mounter consumes'. The two libraries share no classpath
   edge, which is the point of the design and also why nothing verified the
   claim: `gate-test` checks the gate against mount specs this repository wrote
   itself, so it would pass unchanged if the mounter stopped calling the gate,
   renamed a spec key, or started refusing what it permits.

   Here the specs come from `hive-addon`'s own schema, the ordering from its
   solver, and the verdicts from its real `mount!` and `dry-run`. hive-addon is
   a TEST dependency only; the shipped dependency surface is untouched.

   The journey, in the order a buyer lives it:

     1. mint     the vendor issues a signed licence for what was bought
     2. install  the buyer's host installs it as its licence gate
     3. discover the buyer's OWN addon is found on the classpath beside ours
     4. preview  dry-run says what the key unlocks, before anything is mounted
     5. mount    the entitled and the self-owned mount; the unentitled does not
     6. lapse    an expired key stops the proprietary addon and nothing else"
  (:require [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [hive-addon.mount.boundary :as boundary]
            [hive-addon.mount.entitlement :as ent]
            [hive-addon.mount.port :as port]
            [hive-addon.mount.schema :as ms]
            [hive-addon.mount.solve :as solve]
            [hive-addon.protocol :as proto]
            [hive-license.core :as lic]
            [hive-license.crypto :as crypto]
            [hive-license.gate :as gate]
            [hive-license.keyring :as keyring])
  (:import (java.net URL URLClassLoader)
           (java.nio.file Files)
           (java.nio.file.attribute FileAttribute)))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;; ── 1. What the vendor sells, and what this buyer bought ──────────────────

(def ^:private vendor-unit "io.github.hive-agi:hive-carto")
(def ^:private other-unit "io.github.hive-agi:hive-shape")

(def ^:private kp (crypto/generate-keypair))

(def ^:private license
  {:license/id "lic-journey"
   :license/customer-id "acme"
   :license/entitles #{vendor-unit}
   :license/node-id nil
   :license/issued-at "2026-01-01T00:00:00Z"
   :license/expires-at "2026-09-01T00:00:00Z"
   :license/key-id "k-journey"})

(def ^:private signed (lic/issue (:private kp) license))

(defn- gate-at
  "The buyer's licence gate, with the host clock pinned to `now`."
  [now]
  (gate/gate {:signed signed :now-fn (constantly now)}))

(def ^:private during "2026-06-01T00:00:00Z")
(def ^:private after "2027-01-01T00:00:00Z")

;; ── Fake addons: real IAddon instances, resolved by the real mounter ──────

(def mounted (atom []))

(defn- fake-addon [id]
  (reify proto/IAddon
    (addon-id [_] id)
    (addon-type [_] :native)
    (capabilities [_] #{})
    (initialize! [_ _cfg] (swap! mounted conj id) {:success? true})
    (shutdown! [_] nil)
    (tools [_] [])
    (schema-extensions [_] [])
    (health [_] {:status :ok})
    (excluded-tools [_] #{})
    (hooks [_] {})))

(defn make-addon
  "MountSpec constructor. Named by the manifests below, and resolved through
   `requiring-resolve` by the mounter, exactly as a real one is.

   It reads its id from the CONFIG, because that is all a constructor is given:
   the default resolver hands it `:addon/config` and not the spec. An addon that
   returns a different id than its spec registers under that id and is then
   initialized by nobody."
  [config]
  (fake-addon (:addon/id config)))

(use-fixtures :each
  (fn [t]
    (keyring/register! "k-journey" (:public kp))
    (reset! mounted [])
    (t)
    (ent/reset-gate!)
    (keyring/deregister! "k-journey")))

;; ── 3. The buyer's own addon, discovered from the classpath ───────────────

(defn- manifest-edn
  [id unit trust]
  (pr-str (cond-> {:addon/id id
                   :addon/type :native
                   :addon/init-ns "hive-license.journey-test"
                   :addon/init-fn "make-addon"
                   :addon/config {:addon/id id}
                   :addon/trust-class trust}
            unit (assoc :addon/entitlement unit))))

(defn- classpath-root-with
  "A directory holding `name->edn` under META-INF/hive-addons, and a classloader
   that can see it. This is how a buyer's own jar presents its addon: a manifest
   on the classpath, with nothing registered anywhere central."
  [name->edn]
  (let [root (io/file (str (Files/createTempDirectory
                            "journey" (into-array FileAttribute []))))
        dir (io/file root "META-INF/hive-addons")]
    (.mkdirs dir)
    (doseq [[file-name edn] name->edn]
      (spit (io/file dir file-name) edn))
    {:root root
     :loader (URLClassLoader.
              (into-array URL [(.toURL (.toURI root))])
              (.getContextClassLoader (Thread/currentThread)))}))

(def ^:private manifests
  {"vendor-entitled.edn" (manifest-edn "vendor.entitled" vendor-unit :proprietary)
   "vendor-other.edn" (manifest-edn "vendor.other" other-unit :proprietary)
   "acme-own.edn" (manifest-edn "acme.own" nil :foss)})

(defn- discovered []
  (boundary/discover-specs (:loader (classpath-root-with manifests))))

(deftest a-buyer-writes-their-own-addon-and-the-host-finds-it
  (let [{:keys [specs errors]} (discovered)]
    (is (empty? errors))
    (is (= #{"vendor.entitled" "vendor.other" "acme.own"}
           (set (map :addon/id specs)))
        "discovery is open: a manifest on the classpath is an addon, whoever wrote it")
    (testing "and each one validates as a MountSpec, so the gate is judging the
              same value objects the mounter is"
      (is (every? #(nil? (ms/explain ms/MountSpec %)) specs)))))

;; ── 4. Preview: what does this key unlock? ────────────────────────────────

(defn- plan-of [specs] (solve/solve specs))

(deftest dry-run-answers-what-the-key-unlocks-before-anything-mounts
  (let [specs (:specs (discovered))
        report (boundary/dry-run (plan-of specs) (port/atom-mount-host)
                                 {:license-gate (gate-at during)})
        by-id (into {} (map (juxt :addon/id identity)) (:mounted report))]
    (is (:success? (by-id "vendor.entitled")))
    (is (:success? (by-id "acme.own"))
        "a buyer's own addon is :foss, so no gate stands between it and mounting")
    (is (not (:success? (by-id "vendor.other"))))
    (testing "the refusal names the reason, which is what a CLI would print"
      (is (= :entitlement (:phase (by-id "vendor.other"))))
      (is (= :deny/entitlement-missing (:deny/reason (by-id "vendor.other")))))
    (testing "and nothing was constructed to find that out"
      (is (empty? @mounted)))))

;; ── 5. Mount: the key decides, and the host survives a refusal ────────────

(deftest the-minted-key-decides-what-actually-mounts
  (let [specs (:specs (discovered))
        report (boundary/mount! (plan-of specs) (port/atom-mount-host)
                                {:license-gate (gate-at during)})]
    (is (= #{"vendor.entitled" "acme.own"} (set @mounted))
        "only what was bought, plus what the buyer owns outright")
    (is (= #{"vendor.other"} (:skipped report)))
    (testing "a refused addon degrades the report, never the host"
      (is (false? (:ok? report)))
      (is (= 2 (count (filter :success? (:mounted report))))))))

(deftest an-unlicensed-host-mounts-nothing-proprietary
  (testing "the default posture is closed: no gate installed means no gate passed"
    (ent/reset-gate!)
    (let [specs (:specs (discovered))
          report (boundary/mount! (plan-of specs) (port/atom-mount-host) {})]
      (is (= ["acme.own"] @mounted))
      (is (= #{"vendor.entitled" "vendor.other"} (:skipped report))))))

(deftest installing-the-gate-is-what-turns-the-key
  (testing "the buyer installs the licence once, and every later mount sees it"
    (ent/install-gate! (gate-at during))
    (let [specs (:specs (discovered))
          report (boundary/mount! (plan-of specs) (port/atom-mount-host) {})]
      (is (= #{"vendor.entitled" "acme.own"} (set @mounted)))
      (is (= #{"vendor.other"} (:skipped report))))))

;; ── 6. Lapse ──────────────────────────────────────────────────────────────

(deftest an-expired-key-stops-the-proprietary-addon-and-nothing-else
  (let [specs (:specs (discovered))
        report (boundary/mount! (plan-of specs) (port/atom-mount-host)
                                {:license-gate (gate-at after)})]
    (is (= ["acme.own"] @mounted)
        "expiry is not a kill switch for the buyer's own code")
    (is (= #{"vendor.entitled" "vendor.other"} (:skipped report)))))

(deftest a-licence-the-host-cannot-read-refuses-rather-than-permits
  (testing "a missing or unreadable licence file must not mount by accident"
    (let [broken (gate/gate {:signed (fn [] (throw (ex-info "no such file" {})))})
          specs (:specs (discovered))
          report (boundary/mount! (plan-of specs) (port/atom-mount-host)
                                  {:license-gate broken})]
      (is (= ["acme.own"] @mounted))
      (is (= #{"vendor.entitled" "vendor.other"} (:skipped report))))))

;; ── The buyer EXTENDS what they bought, without touching it ───────────────

(def decorated (atom nil))

(defn make-decorator
  "A buyer's addon that wraps the vendor's mounted instance.

   The mounter injects every already-mounted dependency under
   `:mount/dependencies`, so a buyer extends a proprietary addon by composing
   its instance, never by editing it. The vendor jar stays opaque and the
   extension is the buyer's own code."
  [config]
  (let [inner (get (:mount/dependencies config) "vendor.entitled")]
    (reset! decorated (some-> inner proto/addon-id))
    (fake-addon (:addon/id config))))

(deftest a-buyer-extends-a-proprietary-addon-by-composing-its-instance
  (let [{:keys [loader]} (classpath-root-with
                          (assoc manifests
                                 "acme-extension.edn"
                                 (pr-str {:addon/id "acme.extension"
                                          :addon/type :native
                                          :addon/init-ns "hive-license.journey-test"
                                          :addon/init-fn "make-decorator"
                                          :addon/config {:addon/id "acme.extension"}
                                          :addon/dependencies #{"vendor.entitled"}
                                          :addon/trust-class :foss})))
        specs (:specs (boundary/discover-specs loader))
        plan (solve/solve specs)
        report (boundary/mount! plan (port/atom-mount-host)
                                {:license-gate (gate-at during)})]
    (testing "the vendor addon is mounted before the extension that wraps it"
      (is (< (.indexOf ^java.util.List (:order report) "vendor.entitled")
             (.indexOf ^java.util.List (:order report) "acme.extension"))))
    (is (= "vendor.entitled" @decorated)
        "the extension received the live vendor instance, not a copy or a name")
    (is (contains? (set @mounted) "acme.extension"))))

(deftest an-extension-of-an-unlicensed-addon-mounts-without-its-inner
  (testing "the buyer's own code is never held hostage by a refused dependency"
    (reset! decorated ::not-called)
    (let [{:keys [loader]} (classpath-root-with
                            (assoc manifests
                                   "acme-extension.edn"
                                   (pr-str {:addon/id "acme.extension"
                                            :addon/type :native
                                            :addon/init-ns "hive-license.journey-test"
                                            :addon/init-fn "make-decorator"
                                            :addon/config {:addon/id "acme.extension"}
                                            :addon/dependencies #{"vendor.entitled"}
                                            :addon/trust-class :foss})))
          specs (:specs (boundary/discover-specs loader))
          report (boundary/mount! (solve/solve specs) (port/atom-mount-host)
                                  {:license-gate (gate-at after)})]
      (is (contains? (set @mounted) "acme.extension"))
      (is (nil? @decorated)
          "and it can see that the addon it wraps is absent, rather than crashing")
      (is (contains? (:skipped report) "vendor.entitled")))))

;; ── The contract this file exists to hold ─────────────────────────────────

(deftest the-gate-is-consulted-for-gated-specs-and-only-those
  (let [asked (atom [])
        spy (fn [spec] (swap! asked conj (:addon/id spec)) nil)
        specs (:specs (discovered))]
    (boundary/mount! (plan-of specs) (port/atom-mount-host) {:license-gate spy})
    (is (= #{"vendor.entitled" "vendor.other"} (set @asked))
        (str "the mounter must ask about every :proprietary spec and no :foss "
             "one. If this set shrinks, a proprietary addon started mounting "
             "without the gate being asked, and every assertion above would "
             "still pass."))
    (is (= 3 (count @mounted)) "and permitting everything mounts everything")))
