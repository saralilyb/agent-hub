;; Autolith: mcp.sexp in a site-config root. The header value comes from
;; AGENT_HUB_BEARER_AUTOLITH ("Bearer <token>"), which clients/launch
;; derives from AGENT_HUB_TOKEN_AUTOLITH. List in :trusted-read-only-tools
;; only tools that sit in a hub read group: the hub sets readOnlyHint from
;; its own classification, so the two agree.
(:version 1
 :servers
 ((:name "hub"
   :transport
   (:type :http
    :url "http://127.0.0.1:18797/mcp"
    :headers (("Authorization" :environment "AGENT_HUB_BEARER_AUTOLITH"))
    :connect-timeout-seconds 10)
   :approval :read-only
   :trusted-read-only-tools ("todoist_find-tasks"
                             "todoist_find-tasks-by-date")
   :child-tools ("todoist_find-tasks"
                 "todoist_find-tasks-by-date"))))
