(ns paradise.push.main
  (:gen-class)
  (:require [cheshire.core :as json]
            [clojure.edn :as edn]
            [clojure.string :as str]
            [nrepl.server :as nrepl]
            [org.httpkit.server :as http]
            [paradise.push.apns :as apns]
            [paradise.push.fcm :as fcm]
            [paradise.push.router :as router]
            [paradise.push.server :as server]
            [paradise.push.webpush :as webpush])
  (:import [java.util.concurrent Executors]))

(defn- init-app-config [[app-id app-cfg]]
  [app-id
   (case (:type app-cfg)
     :fcm
     (let [sa (json/parse-string (slurp (:service-account-file app-cfg)) true)]
       (assoc app-cfg
              :project-id (or (:project-id app-cfg) (:project_id sa))
              :client-email (:client_email sa)
              :private-key (fcm/load-rsa-private-key (:private_key sa))))

     :apns
     (let [pem (slurp (:keyfile app-cfg))]
       (assoc app-cfg
              :private-key (apns/load-p8-private-key pem)))

     :webpush
     (let [pem     (slurp (:vapid-private-key app-cfg))
           pub-key (-> (or (:vapid-public-key app-cfg)
                           (when-let [f (:vapid-public-key-file app-cfg)]
                             (slurp f)))
                       str/trim)]
       (assoc app-cfg
              :private-key (webpush/load-vapid-private-key pem)
              :public-key  pub-key))

     app-cfg)])

(defn load-config [path]
  (let [raw (edn/read-string (slurp path))]
    (update raw :apps #(into {} (map init-app-config %)))))

(defn- deep-merge [a b]
  (if (and (map? a) (map? b))
    (merge-with deep-merge a b)
    b))

(defn make-dispatcher [apps-config]
  (fn [{:keys [app-id pushkey data default-payload]}]
    (if-let [app-cfg (get apps-config app-id)]
      (case (:type app-cfg)
        :fcm
        (fcm/send-fcm! app-cfg pushkey data)

        :apns
        (let [base-payload (or (:default-payload app-cfg) {})
              merged       (-> base-payload
                               (deep-merge (or default-payload {}))
                               (merge data))]
          (apns/send-apns! app-cfg pushkey merged))

        :webpush
        (webpush/send-webpush! app-cfg pushkey data default-payload)

        {:status :unregistered})
      {:status :unregistered})))

(defn -main [& args]
  (let [cfg-path    (or (System/getenv "CONFIG_PATH") "configs/config.edn")
        cfg         (load-config cfg-path)
        dispatch-fn (make-dispatcher (:apps cfg))
        v-pool      (Executors/newVirtualThreadPerTaskExecutor)
        http-host   (get-in cfg [:http :host] "0.0.0.0")
        http-port   (get-in cfg [:http :port] 5000)]
    (router/watch-routes-dir! (:routes-dir cfg "routes"))
    (when (some #{"--nrepl"} args)
      (let [n-host (get-in cfg [:nrepl :host] "127.0.0.1")
            n-port (get-in cfg [:nrepl :port] 7888)]
        (nrepl/start-server :bind n-host :port n-port)
        (println "nREPL listening on" (str n-host ":" n-port))))
    (http/run-server
     (fn [req] (server/handle-request dispatch-fn req))
     {:ip          http-host
      :port        http-port
      :worker-pool v-pool})
    (println "Loaded apps:" (keys (:apps cfg)))
    (println "Paradise Push Gateway listening on" (str http-host ":" http-port))
    @(promise)))
