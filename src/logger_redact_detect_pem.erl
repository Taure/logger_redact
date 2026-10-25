-module(logger_redact_detect_pem).
-moduledoc "PEM private key blocks, including truncated ones. Class `secret`.".
-behaviour(logger_redact_detector).

-export([init/1, keywords/1, scan/2, class/1]).

init(Opts) ->
    logger_redact_detector:compile(
        ~"(?s)-----BEGIN[A-Z ]*PRIVATE KEY-----.*?(?:-----END[A-Z ]*PRIVATE KEY-----|$)", Opts
    ).

keywords(_State) -> [~"-----BEGIN"].

scan(Text, State) -> logger_redact_detector:regex(Text, State).

class(_State) -> secret.
