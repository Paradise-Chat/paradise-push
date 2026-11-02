(ns paradise.push.server
  (:require [cheshire.core :as json]
            [clojure.java.io :as io]
            [paradise.push.router :as router])
  (:import [java.util.concurrent Callable ExecutorService Executors Future]))

(defonce ^ExecutorService dispatch-executor
  (Executors/newVirtualThreadPerTaskExecutor))

(defn handle-request [dispatch-fn req]
  (if (= (:uri req) "/health")
    {:status  200
     :headers {"Content-Type" "application/json"}
     :body    "{\"status\":\"ok\"}"}
    (if-let [route (get @router/routes-registry (:uri req))]
      (try
        (let [body     (json/parse-stream (io/reader (:body req)) true)
              jobs     ((:normalize route) body)
              futures  (mapv (fn [job]
                               (.submit dispatch-executor
                                        (reify Callable
                                          (call [_]
                                            (try
                                              (let [res (dispatch-fn job)]
                                                (println "Dispatch" (:app-id job) "->" (:status res))
                                                (when (= (:status res) :unregistered)
                                                  (:pushkey job)))
                                              (catch Throwable t
                                                (println "Dispatch exception for" (:app-id job) ":" (.getMessage t))
                                                nil))))))
                             jobs)
              rejected (keep (fn [^Future f] (.get f)) futures)
              resp-map ((:format-response route) rejected)]
          {:status  200
           :headers {"Content-Type" "application/json"}
           :body    (json/generate-string resp-map)})
        (catch Throwable t
          (println "Unhandled error in handle-request:" (.getMessage t))
          {:status  500
           :headers {"Content-Type" "application/json"}
           :body    (json/generate-string {:error (.getMessage t)})}))
      {:status  404
       :headers {"Content-Type" "application/json"}
       :body    "{\"error\":\"Route not found\"}"})))