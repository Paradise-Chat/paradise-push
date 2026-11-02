(ns paradise.push.fcm
  (:require [cheshire.core :as json]
            [clojure.string :as str]
            [paradise.push.apns :as apns])
  (:import [java.net URI URLEncoder]
           [java.net.http HttpClient$Version HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers]
           [java.nio.charset StandardCharsets]
           [java.security KeyFactory Signature]
           [java.security.spec PKCS8EncodedKeySpec]
           [java.time Duration]
           [java.util Base64]))

(defonce oauth-cache (atom {}))

(defn- b64-url [^bytes bs]
  (-> (Base64/getUrlEncoder)
      (.withoutPadding)
      (.encodeToString bs)))

(defn load-rsa-private-key [pem-str]
  (let [clean (-> pem-str
                  (str/replace "-----BEGIN PRIVATE KEY-----" "")
                  (str/replace "-----END PRIVATE KEY-----" "")
                  (str/replace #"\s+" ""))
        der   (.decode (Base64/getDecoder) clean)
        spec  (PKCS8EncodedKeySpec. der)]
    (.generatePrivate (KeyFactory/getInstance "RSA") spec)))

(defn- sign-fcm-assertion [private-key client-email now-sec]
  (let [header  (b64-url (.getBytes (json/generate-string {:alg "RS256" :typ "JWT"}) StandardCharsets/UTF_8))
        claims  (b64-url (.getBytes (json/generate-string
                                     {:iss   client-email
                                      :scope "https://www.googleapis.com/auth/firebase.messaging"
                                      :aud   "https://oauth2.googleapis.com/token"
                                      :iat   now-sec
                                      :exp   (+ now-sec 3600)})
                                    StandardCharsets/UTF_8))
        signing (str header "." claims)
        sig     (doto (Signature/getInstance "SHA256withRSA")
                  (.initSign private-key)
                  (.update (.getBytes signing StandardCharsets/UTF_8)))
        encoded (b64-url (.sign sig))]
    (str signing "." encoded)))

(defn- fetch-access-token! [{:keys [private-key client-email]}]
  (let [now-sec   (quot (System/currentTimeMillis) 1000)
        assertion (sign-fcm-assertion private-key client-email now-sec)
        form-body (str "grant_type="
                       (URLEncoder/encode "urn:ietf:params:oauth:grant-type:jwt-bearer" "UTF-8")
                       "&assertion="
                       (URLEncoder/encode assertion "UTF-8"))
        req       (-> (HttpRequest/newBuilder (URI/create "https://oauth2.googleapis.com/token"))
                      (.timeout (Duration/ofSeconds 10))
                      (.header "Content-Type" "application/x-www-form-urlencoded")
                      (.POST (HttpRequest$BodyPublishers/ofString form-body StandardCharsets/UTF_8))
                      (.build))
        resp      (.send apns/http2-client req (HttpResponse$BodyHandlers/ofString))
        parsed    (json/parse-string (.body resp) true)
        token     (:access_token parsed)]
    (when-not token
      (throw (ex-info "Failed to obtain FCM OAuth2 token" {:status (.statusCode resp) :body (.body resp)})))
    (swap! oauth-cache assoc client-email {:access-token token :expires-at (+ now-sec 3300)})
    token))

(defn get-access-token [{:keys [client-email] :as fcm-config}]
  (let [now-sec (quot (System/currentTimeMillis) 1000)
        {:keys [access-token expires-at]} (get @oauth-cache client-email)]
    (if (and access-token (< now-sec expires-at))
      access-token
      (fetch-access-token! fcm-config))))

(defn send-fcm! [{:keys [project-id] :as fcm-config} device-token data-map]
  (let [token (get-access-token fcm-config)
        uri   (URI/create (str "https://fcm.googleapis.com/v1/projects/" project-id "/messages:send"))
        body  (json/generate-string
               {:message
                {:token   device-token
                 :data    (into {} (map (fn [[k v]] [(name k) (str v)]) data-map))
                 :android {:priority "HIGH"}}})
        req   (-> (HttpRequest/newBuilder uri)
                  (.version HttpClient$Version/HTTP_2)
                  (.timeout (Duration/ofSeconds 10))
                  (.header "Authorization" (str "Bearer " token))
                  (.header "Content-Type" "application/json")
                  (.POST (HttpRequest$BodyPublishers/ofString body StandardCharsets/UTF_8))
                  (.build))
        resp  (.send apns/http2-client req (HttpResponse$BodyHandlers/ofString))
        code  (.statusCode resp)]
    (cond
      (= code 200) {:status :ok}
      (or (= code 404) (= code 410)) {:status :unregistered :body (.body resp)}
      (and (= code 400)
           (or (str/includes? (.body resp) "UNREGISTERED")
               (str/includes? (.body resp) "INVALID_ARGUMENT")))
      {:status :unregistered :body (.body resp)}
      :else {:status :transient-error :code code :body (.body resp)})))