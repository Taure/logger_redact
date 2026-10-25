-module(logger_redact_detect_pan).
-moduledoc "Payment card numbers: 13 to 19 digits starting 2 to 6, optionally grouped, that pass Luhn. Class `pan`.".
-behaviour(logger_redact_detector).

-export([init/1, keywords/1, scan/2, class/1]).

init(Opts) ->
    logger_redact_detector:compile(~"(?<![0-9])[2-6](?:[ -]?[0-9]){12,18}(?![0-9])", Opts).

keywords(_State) -> [<<D>> || D <- lists:seq($2, $6)].

scan(Text, State) ->
    case logger_redact_detector:regex(Text, State) of
        error -> error;
        Spans -> [Span || Span <- Spans, valid(binary:part(Text, Span))]
    end.

class(_State) -> pan.

valid(Candidate) ->
    Digits = logger_redact_detector:digits(Candidate),
    length(Digits) >= 13 andalso logger_redact_detector:luhn(Digits).
