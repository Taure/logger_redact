-module(logger_redact_detect_jwt).
-moduledoc "JSON Web Tokens (`eyJ...`). Class `credential`.".
-behaviour(logger_redact_detector).

-export([init/1, keywords/1, scan/2, class/1]).

init(Opts) ->
    logger_redact_detector:compile(
        ~"eyJ[A-Za-z0-9_-]{4,}\\.[A-Za-z0-9_-]{4,}(?:\\.[A-Za-z0-9_-]*)?", Opts
    ).

keywords(_State) -> [~"eyJ"].

scan(Text, State) -> logger_redact_detector:regex(Text, State).

class(_State) -> credential.
