-module(logger_redact_detect_phone).
-moduledoc """
Phone numbers in international form (`+46 70 123 45 67`, `+4670-1234567`).
National forms without a `+` are too ambiguous to detect in free text, so log
them under a key such as `phone` or `msisdn`. Class `phone`.
""".
-behaviour(logger_redact_detector).

-export([init/1, keywords/1, scan/2, class/1]).

init(Opts) ->
    logger_redact_detector:compile(~"\\+[1-9](?:[ -]?\\(?[0-9]\\)?){6,14}(?![0-9])", Opts).

keywords(_State) -> [~"+"].

scan(Text, State) -> logger_redact_detector:regex(Text, State).

class(_State) -> phone.
