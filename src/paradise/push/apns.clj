(ns paradise.push.apns
  (:require [cheshire.core :as json]
            [clojure.string :as str])
  (:import [java.net URI]
           [java.net.http HttpClient HttpClient$Version HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers]
           [java.nio.charset StandardCharsets]
           [java.security KeyFactory Signature]
           [java.security.spec PKCS8EncodedKeySpec]
           [java.time Duration]
           [java.util Base64]))

(defonce http2-client
  (-> (HttpClient/newBuilder)
      (.version HttpClient$Version/HTTP_2)
      (.connectTimeout (Duration/ofSeconds 10))
      (.build)))

(defonce token-cache (atom {}))

(defn- b64-url [^bytes bs]
  (-> (Base64/getUrlEncoder)
      (.withoutPadding)
      (.encodeToString bs)))

(defn load-p8-private-key [pem-str]
  (let [clean (-> pem-str
                  (str/replace "-----BEGIN PRIVATE KEY-----" "")
                  (str/replace "-----END PRIVATE KEY-----" "")
                  (str/replace #"\s+" ""))
        der   (.decode (Base64/getDecoder) clean)
        spec  (PKCS8EncodedKeySpec. der)]
    (.generatePrivate (KeyFactory/getInstance "EC") spec)))

(defn- sign-apns-jwt [private-key key-id team-id now-sec]
  (let [header  (b64-url (.getBytes (json/generate-string {:alg "ES256" :kid key-id}) StandardCharsets/UTF_8))
        claims  (b64-url (.getBytes (json/generate-string {:iss team-id :iat now-sec}) StandardCharsets/UTF_8))
        signing (str header "." claims)
        sig     (doto (Signature/getInstance "SHA256withECDSAinP1363Format")
                  (.initSign private-key)
                  (.update (.getBytes signing StandardCharsets/UTF_8)))
        encoded (b64-url (.sign sig))]
    (str signing "." encoded)))

(defn get-apns-jwt [private-key key-id team-id]
  (let [now-sec   (quot (System/currentTimeMillis) 1000)
        cache-key [key-id team-id]
        {:keys [jwt issued-at]} (get @token-cache cache-key)]
    (if (and jwt (< (- now-sec issued-at) 3000))
      jwt
      (let [fresh (sign-apns-jwt private-key key-id team-id now-sec)]
        (swap! token-cache assoc cache-key {:jwt fresh :issued-at now-sec})
        fresh))))

(defn send-apns! [{:keys [private-key key-id team-id topic sandbox?]} device-token payload-map]
  (let [host       (if sandbox? "https://api.sandbox.push.apple.com" "https://api.push.apple.com")
        uri        (URI/create (str host "/3/device/" device-token))
        jwt        (get-apns-jwt private-key key-id team-id)
        has-alert? (some? (or (get-in payload-map [:aps :alert])
                              (get-in payload-map ["aps" "alert"])))
        push-type  (if has-alert? "alert" "background")
        priority   (if has-alert? "10" "5")
        body       (json/generate-string payload-map)
        req        (-> (HttpRequest/newBuilder uri)
                       (.version HttpClient$Version/HTTP_2)
                       (.timeout (Duration/ofSeconds 10))
                       (.header "authorization" (str "bearer " jwt))
                       (.header "apns-topic" topic)
                       (.header "apns-push-type" push-type)
                       (.header "apns-priority" priority)
                       (.POST (HttpRequest$BodyPublishers/ofString body StandardCharsets/UTF_8))
                       (.build))
        resp       (.send http2-client req (HttpResponse$BodyHandlers/ofString))]
    (case (.statusCode resp)
      200 {:status :ok}
      (400 410) {:status :unregistered :body (.body resp)}
      {:status :transient-error :code (.statusCode resp) :body (.body resp)})))