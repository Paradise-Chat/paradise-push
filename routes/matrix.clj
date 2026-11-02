{:path "/_matrix/push/v1/notify"
 :engine "matrix"
 :script "push-matrix.js"
 :normalize
 (fn [body]
   (let [notif    (:notification body)
         event-id (:event_id notif)
         room-id  (:room_id notif)
         unread   (get-in notif [:counts :unread])
         devices  (:devices notif)]
     (if (and (string? event-id) (string? room-id))
       (mapv (fn [dev]
               {:app-id          (:app_id dev)
                :pushkey         (:pushkey dev)
                :default-payload (get-in dev [:data :default_payload])
                :data            (cond-> {"engine"   "matrix"
                                          "script"   "push-matrix.js"
                                          "event_id" event-id
                                          "room_id"  room-id}
                                   unread (assoc "unread" (str unread)))})
             devices)
       [])))
 :format-response
 (fn [rejected-tokens]
   {:rejected (vec rejected-tokens)})}