-module(logger_redact_detect_email).
-moduledoc "Email addresses. Class `email`.".
-behaviour(logger_redact_detector).

-export([init/1, keywords/1, scan/2, class/1]).

init(Opts) ->
    logger_redact_detector:compile(~"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}", Opts).

keywords(_State) -> [~"@"].

scan(Text, State) -> logger_redact_detector:regex(Text, State).

class(_State) -> email.
