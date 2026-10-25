-module(logger_redact_detect_url_userinfo).
-moduledoc "The `user:password` part of a URL such as `postgres://user:password@host/db`. Class `secret`.".
-behaviour(logger_redact_detector).

-export([init/1, keywords/1, scan/2, class/1]).

init(Opts) ->
    logger_redact_detector:compile(~"[A-Za-z][A-Za-z0-9+.-]*://([^/\\s:@]+:[^/\\s@]+)@", Opts).

keywords(_State) -> [~"://"].

scan(Text, State) -> logger_redact_detector:regex(Text, State, 1).

class(_State) -> secret.
