(ns paradise.push.router
  (:require [clojure.java.io :as io]
            [clojure.string :as str])
  (:import [java.nio.file FileSystems Paths StandardWatchEventKinds]))

(defonce routes-registry (atom {}))

(defn load-route-file! [^java.io.File f]
  (when (and (.isFile f)
             (str/ends-with? (.getName f) ".clj")
             (not (str/starts-with? (.getName f) "."))
             (not (str/starts-with? (.getName f) "#")))
    (try
      (let [spec (load-file (.getAbsolutePath f))]
        (when (and (map? spec) (:path spec) (:normalize spec))
          (swap! routes-registry assoc (:path spec) spec)
          (println "Loaded route:" (:path spec) "from" (.getName f))))
      (catch Throwable t
        (println "Failed to load route file:" (.getName f) (.getMessage t))))))

(defn reload-all-routes! [^java.io.File dir]
  (when-let [files (.listFiles dir)]
    (doseq [f files]
      (load-route-file! f))))

(defn watch-routes-dir! [dir-path]
  (let [dir (io/file dir-path)]
    (.mkdirs dir)
    (reload-all-routes! dir)
    (Thread/startVirtualThread
     (fn []
       (let [watcher (.newWatchService (FileSystems/getDefault))
             path    (Paths/get (.toURI dir))]
         (.register path watcher
                    (into-array [StandardWatchEventKinds/ENTRY_CREATE
                                 StandardWatchEventKinds/ENTRY_MODIFY
                                 StandardWatchEventKinds/ENTRY_DELETE]))
         (loop []
           (let [wk (.take watcher)]
             (.pollEvents wk)
             (reload-all-routes! dir)
             (when (.reset wk)
               (recur)))))))))