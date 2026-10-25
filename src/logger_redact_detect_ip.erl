-module(logger_redact_detect_ip).
-moduledoc """
IPv4 and IPv6 addresses. Not in the default detector list, because version
strings and node names make it noisy in free text. Class `ip`.
""".
-behaviour(logger_redact_detector).

-export([init/1, keywords/1, scan/2, class/1]).

init(Opts) ->
    logger_redact_detector:compile(
        ~"(?<![0-9.])(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?![0-9.])|(?<![0-9A-Za-z:.])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,6}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,5})?)(?![0-9A-Za-z:])",
        Opts
    ).

keywords(_State) -> [~".", ~":"].

scan(Text, State) -> logger_redact_detector:regex(Text, State).

class(_State) -> ip.
