-module(logger_redact_detect_iban).
-moduledoc "IBANs, compact or in groups of four, that pass the mod-97 check. Class `iban`.".
-behaviour(logger_redact_detector).

-export([init/1, keywords/1, scan/2, class/1]).

init(Opts) ->
    logger_redact_detector:compile(
        ~"\\b[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\\b", Opts
    ).

keywords(_State) -> [<<D>> || D <- lists:seq($0, $9)].

scan(Text, State) ->
    case logger_redact_detector:regex(Text, State) of
        error -> error;
        Spans -> [Span || Span <- Spans, valid(binary:part(Text, Span))]
    end.

class(_State) -> iban.

valid(Candidate) ->
    case <<<<C>> || <<C>> <= Candidate, C =/= $\s>> of
        <<Country:4/binary, Rest/binary>> when byte_size(Rest) >= 11 ->
            mod97(<<Rest/binary, Country/binary>>, 0) =:= 1;
        _ ->
            false
    end.

mod97(<<>>, Acc) ->
    Acc;
mod97(<<C, Rest/binary>>, Acc) when C >= $0, C =< $9 ->
    mod97(Rest, (Acc * 10 + C - $0) rem 97);
mod97(<<C, Rest/binary>>, Acc) ->
    mod97(Rest, (Acc * 100 + C - $A + 10) rem 97).
