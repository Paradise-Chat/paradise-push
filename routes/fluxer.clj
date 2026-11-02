{:path "/v1/push/fluxer"
 :engine "fluxer"
 :script "push-fluxer.js"
 :normalize
 (fn [body]
   (let [event-id   (:event_id body)
         room-id    (:room_id body)
         account-id (:account_id body)]
     (if (and (string? event-id) (string? room-id))
       [{:app-id  (:app_id body)
         :pushkey (:pushkey body)
         :data    (cond-> {"engine"   "fluxer"
                           "script"   "push-fluxer.js"
                           "event_id" event-id
                           "room_id"  room-id}
                    account-id (assoc "account_id" account-id))}]
       [])))
 :format-response
 (fn [rejected-tokens]
   {:rejected (vec rejected-tokens)})}