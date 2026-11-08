(ns paradise.push.webpush
  (:require [cheshire.core :as json]
            [clojure.string :as str]
            [paradise.push.apns :as apns])
  (:import [java.math BigInteger]
           [java.net URI]
           [java.net.http HttpClient$Version HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers]
           [java.nio ByteBuffer]
           [java.nio.charset StandardCharsets]
           [java.security AlgorithmParameters KeyFactory KeyPairGenerator SecureRandom Signature]
           [java.security.interfaces ECPublicKey]
           [java.security.spec ECGenParameterSpec ECParameterSpec ECPoint ECPrivateKeySpec ECPublicKeySpec PKCS8EncodedKeySpec]
           [java.time Duration]
           [java.util Arrays Base64]
           [javax.crypto Cipher KeyAgreement Mac]
           [javax.crypto.spec GCMParameterSpec SecretKeySpec]))

(defonce ^SecureRandom secure-random (SecureRandom.))

(defn- b64-url-encode [^bytes bs]
  (-> (Base64/getUrlEncoder)
      (.withoutPadding)
      (.encodeToString bs)))

(defn- b64-url-decode ^bytes [^String s]
  (let [clean (-> s
                  str/trim
                  (str/replace "+" "-")
                  (str/replace "/" "_")
                  (str/replace #"=+$" ""))]
    (.decode (Base64/getUrlDecoder) clean)))

(defn- p256-parameter-spec ^ECParameterSpec []
  (let [params (doto (AlgorithmParameters/getInstance "EC")
                 (.init (ECGenParameterSpec. "secp256r1")))]
    (.getParameterSpec params ECParameterSpec)))

(defn load-vapid-private-key [key-str]
  (let [trimmed (str/trim key-str)
        kf      (KeyFactory/getInstance "EC")]
    (cond
      (str/includes? trimmed "BEGIN PRIVATE KEY")
      (let [clean (-> trimmed
                      (str/replace "-----BEGIN PRIVATE KEY-----" "")
                      (str/replace "-----END PRIVATE KEY-----" "")
                      (str/replace #"\s+" ""))
            der   (.decode (Base64/getDecoder) clean)]
        (.generatePrivate kf (PKCS8EncodedKeySpec. der)))

      (str/includes? trimmed "BEGIN EC PRIVATE KEY")
      (let [clean  (-> trimmed
                       (str/replace "-----BEGIN EC PRIVATE KEY-----" "")
                       (str/replace "-----END EC PRIVATE KEY-----" "")
                       (str/replace #"\s+" ""))
            der    (.decode (Base64/getDecoder) clean)
            scalar (Arrays/copyOfRange der 7 39)]
        (.generatePrivate kf (ECPrivateKeySpec. (BigInteger. 1 scalar) (p256-parameter-spec))))

      :else
      (let [raw (b64-url-decode trimmed)]
        (if (= (alength raw) 32)
          (.generatePrivate kf (ECPrivateKeySpec. (BigInteger. 1 raw) (p256-parameter-spec)))
          (.generatePrivate kf (PKCS8EncodedKeySpec. raw)))))))

(defn- big-int->32-bytes ^bytes [^BigInteger bi]
  (let [raw (.toByteArray bi)
        len (alength raw)]
    (cond
      (= len 32) raw
      (> len 32) (Arrays/copyOfRange raw (- len 32) len)
      :else      (let [out (byte-array 32)]
                   (System/arraycopy raw 0 out (- 32 len) len)
                   out))))

(defn- ec-public-key->bytes ^bytes [^ECPublicKey pub-key]
  (let [w   (.getW pub-key)
        x   (big-int->32-bytes (.getAffineX w))
        y   (big-int->32-bytes (.getAffineY w))
        out (byte-array 65)]
    (aset-byte out 0 4)
    (System/arraycopy x 0 out 1 32)
    (System/arraycopy y 0 out 33 32)
    out))

(defn- bytes->ec-public-key ^ECPublicKey [^bytes uncompressed]
  (when (or (not= (alength uncompressed) 65)
            (not= (aget uncompressed 0) 4))
    (throw (ex-info "Invalid uncompressed P-256 public key" {:length (alength uncompressed)})))
  (let [x     (BigInteger. 1 (Arrays/copyOfRange uncompressed 1 33))
        y     (BigInteger. 1 (Arrays/copyOfRange uncompressed 33 65))
        point (ECPoint. x y)
        spec  (ECPublicKeySpec. point (p256-parameter-spec))]
    (.generatePublic (KeyFactory/getInstance "EC") spec)))

(defn- concat-bytes ^bytes [& byte-arrays]
  (let [total (reduce + (map alength byte-arrays))
        out   (byte-array total)]
    (loop [offset 0
           arrs   byte-arrays]
      (when-let [^bytes a (first arrs)]
        (System/arraycopy a 0 out offset (alength a))
        (recur (+ offset (alength a)) (rest arrs))))
    out))

(defn- hmac-sha256 ^bytes [^bytes key-bytes ^bytes data-bytes]
  (let [mac (Mac/getInstance "HmacSHA256")]
    (.init mac (SecretKeySpec. key-bytes "HmacSHA256"))
    (.doFinal mac data-bytes)))

(defn- hkdf-expand ^bytes [^bytes prk ^bytes info ^long length]
  (let [block (hmac-sha256 prk (concat-bytes info (byte-array [1])))]
    (Arrays/copyOfRange block 0 (int length))))

(defn- encrypt-aes128gcm ^bytes [^bytes plaintext ^String p256dh-b64 ^String auth-b64]
  (let [ua-pub-bytes (b64-url-decode p256dh-b64)
        auth-secret  (b64-url-decode auth-b64)
        ua-pub-key   (bytes->ec-public-key ua-pub-bytes)
        kpg          (doto (KeyPairGenerator/getInstance "EC")
                       (.initialize (ECGenParameterSpec. "secp256r1") secure-random))
        as-kp        (.generateKeyPair kpg)
        as-pub-bytes (ec-public-key->bytes (.getPublic as-kp))
        ka           (doto (KeyAgreement/getInstance "ECDH")
                       (.init (.getPrivate as-kp))
                       (.doPhase ua-pub-key true))
        ecdh-secret  (.generateSecret ka)
        salt         (let [s (byte-array 16)]
                       (.nextBytes secure-random s)
                       s)
        prk-key      (hmac-sha256 auth-secret ecdh-secret)
        key-info     (concat-bytes (.getBytes "WebPush: info\u0000" StandardCharsets/UTF_8)
                                   ua-pub-bytes
                                   as-pub-bytes)
        ikm          (hkdf-expand prk-key key-info 32)
        prk          (hmac-sha256 salt ikm)
        cek-info     (.getBytes "Content-Encoding: aes128gcm\u0000" StandardCharsets/UTF_8)
        nonce-info   (.getBytes "Content-Encoding: nonce\u0000" StandardCharsets/UTF_8)
        cek          (hkdf-expand prk cek-info 16)
        nonce        (hkdf-expand prk nonce-info 12)
        padded       (concat-bytes plaintext (byte-array [2]))
        cipher       (doto (Cipher/getInstance "AES/GCM/NoPadding")
                       (.init Cipher/ENCRYPT_MODE
                              (SecretKeySpec. cek "AES")
                              (GCMParameterSpec. 128 nonce)))
        ciphertext   (.doFinal cipher padded)
        header-buf   (doto (ByteBuffer/allocate 86)
                       (.put salt)
                       (.putInt 4096)
                       (.put (byte 65))
                       (.put as-pub-bytes))]
    (concat-bytes (.array header-buf) ciphertext)))

(defn- format-subject [contact]
  (let [s (or contact "mailto:admin@localhost")]
    (if (or (str/starts-with? s "mailto:")
            (str/starts-with? s "https://"))
      s
      (str "mailto:" s))))

(defn- sign-vapid-jwt [private-key audience subject]
  (let [now-sec (quot (System/currentTimeMillis) 1000)
        header  (b64-url-encode (.getBytes (json/generate-string {:typ "JWT" :alg "ES256"}) StandardCharsets/UTF_8))
        claims  (b64-url-encode (.getBytes (json/generate-string {:aud audience
                                                                  :exp (+ now-sec 43200)
                                                                  :sub subject})
                                           StandardCharsets/UTF_8))
        signing (str header "." claims)
        sig     (doto (Signature/getInstance "SHA256withECDSAinP1363Format")
                  (.initSign private-key)
                  (.update (.getBytes signing StandardCharsets/UTF_8)))
        encoded (b64-url-encode (.sign sig))]
    (str signing "." encoded)))

(defn send-webpush! [{:keys [private-key public-key vapid-contact-email default-payload]} pushkey data-map route-default-payload]
  (let [endpoint (or (:endpoint data-map) (get data-map "endpoint"))
        auth     (or (:auth data-map) (get data-map "auth"))
        p256dh   (or pushkey (:p256dh data-map) (get data-map "p256dh"))]
    (if (or (str/blank? endpoint) (str/blank? auth) (str/blank? p256dh))
      {:status :unregistered :body "Missing WebPush endpoint, auth, or p256dh"}
      (let [uri         (URI/create endpoint)
            audience    (str (.getScheme uri) "://" (.getAuthority uri))
            subject     (format-subject vapid-contact-email)
            jwt         (sign-vapid-jwt private-key audience subject)
            clean-data  (dissoc data-map :endpoint :auth :url "endpoint" "auth" "url")
            payload-map (merge (or default-payload {})
                               (or route-default-payload {})
                               clean-data)
            plaintext   (.getBytes (json/generate-string payload-map) StandardCharsets/UTF_8)
            encrypted   (encrypt-aes128gcm plaintext p256dh auth)
            req         (-> (HttpRequest/newBuilder uri)
                            (.version HttpClient$Version/HTTP_2)
                            (.timeout (Duration/ofSeconds 10))
                            (.header "Authorization" (str "vapid t=" jwt ", k=" public-key))
                            (.header "Content-Type" "application/octet-stream")
                            (.header "Content-Encoding" "aes128gcm")
                            (.header "TTL" "86400")
                            (.header "Urgency" "high")
                            (.POST (HttpRequest$BodyPublishers/ofByteArray encrypted))
                            (.build))
            resp        (.send apns/http2-client req (HttpResponse$BodyHandlers/ofString))
            code        (.statusCode resp)]
        (cond
          (<= 200 code 299)             {:status :ok}
          (or (= code 404) (= code 410)) {:status :unregistered :body (.body resp)}
          :else                         {:status :transient-error :code code :body (.body resp)})))))
