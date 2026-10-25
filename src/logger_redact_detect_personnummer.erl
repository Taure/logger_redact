-module(logger_redact_detect_personnummer).
-moduledoc """
Swedish personnummer and samordningsnummer in `YYMMDD-NNNN`, `YYMMDD+NNNN`,
`YYYYMMDDNNNN` and related forms, checked by date and Luhn. Class `national_id`.
""".
-behaviour(logger_redact_detector).

-export([init/1, keywords/1, scan/2, class/1]).

init(Opts) ->
    logger_redact_detector:compile(
        ~"(?<![0-9])(?:(?:19|20)[0-9]{2}|[0-9]{2})[0-9]{4}[-+]?[0-9]{4}(?![0-9])", Opts
    ).

keywords(_State) -> [<<D>> || D <- lists:seq($0, $9)].

scan(Text, State) ->
    case logger_redact_detector:regex(Text, State) of
        error ->
            error;
        Spans ->
            [Span || Span <- Spans, valid(logger_redact_detector:digits(binary:part(Text, Span)))]
    end.

class(_State) -> national_id.

valid([_, _ | Ten]) when length(Ten) =:= 10 ->
    valid(Ten);
valid([_, _, M1, M2, D1, D2, _, _, _, _] = Ten) ->
    Month = M1 * 10 + M2,
    Day = D1 * 10 + D2,
    Month >= 1 andalso Month =< 12 andalso
        ((Day >= 1 andalso Day =< 31) orelse (Day >= 61 andalso Day =< 91)) andalso
        logger_redact_detector:luhn(Ten);
valid(_Digits) ->
    false.
