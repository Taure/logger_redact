-module(logger_redact_detect_bearer).
-moduledoc "Credentials after an HTTP `Bearer` or `Basic` scheme. The scheme is kept. Class `credential`.".
-behaviour(logger_redact_detector).

-export([init/1, keywords/1, scan/2, class/1]).

init(Opts) ->
    logger_redact_detector:compile(~"(?i)\\b(?:bearer|basic)\\s+([A-Za-z0-9._~+/=-]{8,})", Opts).

keywords(_State) -> [~"Bearer", ~"bearer", ~"BEARER", ~"Basic", ~"basic", ~"BASIC"].

scan(Text, State) -> logger_redact_detector:regex(Text, State, 1).

class(_State) -> credential.
