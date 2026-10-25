-module(logger_redact_text).
-moduledoc false.

-export([scan/2, replacement/3, dropped/1]).

-define(TRUNCATED(Bytes), iolist_to_binary([~"[TRUNCATED bytes=", integer_to_binary(Bytes), ~"]"])).

-spec scan(binary(), logger_redact_policy:policy()) -> binary().
scan(Binary, #{max_scan_bytes := Max} = Policy) when byte_size(Binary) > Max ->
    Head = utf8_prefix(binary:part(Binary, 0, Max)),
    Dropped = byte_size(Binary) - byte_size(Head),
    <<(scan(Head, Policy))/binary, (?TRUNCATED(Dropped))/binary>>;
scan(Binary, #{prefilter := none}) ->
    Binary;
scan(Binary, #{prefilter := Prefilter, detectors := Detectors} = Policy) ->
    case Prefilter =:= all orelse binary:match(Binary, Prefilter) =/= nomatch of
        true -> detect(Binary, Detectors, [], Policy);
        false -> Binary
    end.

-spec replacement(logger_redact_policy:class(), binary(), logger_redact_policy:policy()) ->
    binary().
replacement(Class, Value, #{actions := Actions, hmac_bytes := Bytes}) ->
    case maps:get(Class, Actions, drop) of
        keep ->
            Value;
        hmac ->
            case logger_redact_key:pseudonym(Class, Value, Bytes) of
                {ok, Pseudonym} -> iolist_to_binary([$[, atom_to_binary(Class), $:, Pseudonym, $]]);
                error -> dropped(Class)
            end;
        drop ->
            dropped(Class)
    end.

-spec dropped(logger_redact_policy:class()) -> binary().
dropped(Class) ->
    iolist_to_binary([~"[REDACTED:", atom_to_binary(Class), $]]).

detect(Binary, [], Spans, Policy) ->
    case Spans of
        [] -> Binary;
        _ -> splice(Binary, 0, merge(lists:sort(Spans)), Policy)
    end;
detect(
    Binary,
    [#{module := Module, state := State, class := Class, keywords := Keywords} | Rest],
    Spans,
    Policy
) ->
    case Keywords =:= all orelse binary:match(Binary, Keywords) =/= nomatch of
        false ->
            detect(Binary, Rest, Spans, Policy);
        true ->
            case Module:scan(Binary, State) of
                error -> dropped(Class);
                Found -> detect(Binary, Rest, [{S, L, Class} || {S, L} <- Found] ++ Spans, Policy)
            end
    end.

%% Overlapping spans are joined, so no part of either match survives.
merge([{S1, L1, Class}, {S2, L2, _} | Rest]) when S2 < S1 + L1 ->
    merge([{S1, max(L1, S2 + L2 - S1), Class} | Rest]);
merge([Span | Rest]) ->
    [Span | merge(Rest)];
merge([]) ->
    [].

splice(Binary, At, [], _Policy) ->
    binary:part(Binary, At, byte_size(Binary) - At);
splice(Binary, At, [{Start, Length, Class} | Rest], Policy) ->
    Replacement = replacement(Class, binary:part(Binary, Start, Length), Policy),
    Tail = splice(Binary, Start + Length, Rest, Policy),
    <<(binary:part(Binary, At, Start - At))/binary, Replacement/binary, Tail/binary>>.

utf8_prefix(Binary) ->
    case unicode:characters_to_binary(Binary) of
        {incomplete, Valid, _} -> Valid;
        _ -> Binary
    end.
