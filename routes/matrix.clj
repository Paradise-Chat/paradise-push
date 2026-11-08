{:path "/_matrix/push/v1/notify"
 :engine "matrix"
 :script "push-matrix.js"
 :normalize
 (fn [body]
   (let [notif        (:notification body)
         event-id     (:event_id notif)
         room-id      (:room_id notif)
         ev-type      (:type notif)
         sender       (:sender notif)
         sender-name  (:sender_display_name notif)
         room-name    (:room_name notif)
         room-alias   (:room_alias notif)
         prio         (:prio notif)
         membership   (:membership notif)
         msgtype      (get-in notif [:content :msgtype])
         msgbody      (get-in notif [:content :body])
         unread       (get-in notif [:counts :unread])
         missed-calls (get-in notif [:counts :missed_calls])
         devices      (:devices notif)]
     (if (and (string? event-id) (string? room-id))
       (mapv (fn [dev]
               (let [account-id  (or (get-in dev [:data :account_id])
                                     (get-in dev [:data :user_id]))
                     endpoint    (get-in dev [:data :endpoint])
                     auth        (get-in dev [:data :auth])
                     p256dh      (get-in dev [:data :p256dh])
                     dev-payload (or (get-in dev [:data :default_payload]) {})]
                 {:app-id          (:app_id dev)
                  :pushkey         (:pushkey dev)
                  :default-payload (cond-> dev-payload
                                     (number? unread) (assoc-in [:aps :badge] unread))
                  :data            (cond-> {"engine"   "matrix"
                                            "script"   "push-matrix.js"
                                            "event_id" event-id
                                            "room_id"  room-id}
                                     ev-type      (assoc "type" (str ev-type))
                                     sender       (assoc "sender" (str sender))
                                     sender-name  (assoc "sender_display_name" (str sender-name))
                                     room-name    (assoc "room_name" (str room-name))
                                     room-alias   (assoc "room_alias" (str room-alias))
                                     prio         (assoc "prio" (str prio))
                                     membership   (assoc "membership" (str membership))
                                     msgtype      (assoc "content_msgtype" (str msgtype))
                                     msgbody      (assoc "content_body" (str msgbody))
                                     unread       (assoc "unread" (str unread))
                                     missed-calls (assoc "missed_calls" (str missed-calls))
                                     account-id   (assoc "account_id" (str account-id))
                                     endpoint     (assoc "endpoint" (str endpoint))
                                     auth         (assoc "auth" (str auth))
                                     p256dh       (assoc "p256dh" (str p256dh)))}))
             devices)
       [])))
 :format-response
 (fn [rejected-tokens]
   {:rejected (vec rejected-tokens)})}