-module(logger_redact_detector).
-moduledoc ~"""
Behaviour for value detectors that find sensitive spans in text.

A detector is configured as `Module` or `{Module, Opts}` in the policy's
`detectors` list. `init/1` runs once when the policy is compiled; the other
callbacks run per scanned binary and must be cheap.

`keywords/1` returns literal anchors. Text that contains none of them is never
passed to `scan/2`. Return `[]` to be called for every binary.

`scan/2` returns the byte spans to redact, or `error` when the scan could not
complete (for example a regex match limit). An error redacts the whole binary.

```erlang
-module(my_detect_ticket).
-behaviour(logger_redact_detector).
-export([init/1, keywords/1, scan/2, class/1]).

init(Opts) -> logger_redact_detector:compile(~"TCK-[0-9]{8}", Opts).
keywords(_State) -> [~"TCK-"].
scan(Text, State) -> logger_redact_detector:regex(Text, State).
class(_State) -> ticket.
```
""".

-export([compile/2, regex/2, regex/3, luhn/1, digits/1]).

-export_type([span/0, regex_state/0]).

-type span() :: {Start :: non_neg_integer(), Length :: pos_integer()}.
-opaque regex_state() :: #{mp := re:mp(), match_limit := pos_integer()}.

-callback init(Opts :: map()) -> State :: term().
-callback keywords(State :: term()) -> [binary()].
-callback scan(Text :: binary(), State :: term()) -> [span()] | error.
-callback class(State :: term()) -> atom().

-doc "Compiles `Pattern` for use with `regex/2,3`, taking `match_limit` from `Opts`.".
-spec compile(iodata(), map()) -> regex_state().
compile(Pattern, Opts) ->
    {ok, {re_pattern, _, _, _, _} = MP} = re:compile(Pattern, [unicode]),
    case maps:get(match_limit, Opts, 100000) of
        Limit when is_integer(Limit), Limit > 0 -> #{mp => MP, match_limit => Limit}
    end.

-doc "All match spans of the compiled pattern. A match limit hit returns `error`.".
-spec regex(binary(), regex_state()) -> [span()] | error.
regex(Text, State) ->
    regex(Text, State, 0).

-doc "All spans of capture group `Group` (0 is the whole match).".
-spec regex(binary(), regex_state(), non_neg_integer()) -> [span()] | error.
regex(Text, #{mp := MP, match_limit := Limit}, Group) ->
    case
        re:run(Text, MP, [global, {capture, [Group], index}, {match_limit, Limit}, report_errors])
    of
        nomatch -> [];
        {match, Matches} -> [Span || [{_, Length} = Span] <- Matches, Length > 0];
        {error, _} -> error
    end.

-doc "True if the digit list passes the Luhn checksum.".
-spec luhn([0..9]) -> boolean().
luhn(Digits) ->
    luhn(lists:reverse(Digits), 0, 0) rem 10 =:= 0.

luhn([], _Index, Sum) ->
    Sum;
luhn([D | Rest], Index, Sum) when Index rem 2 =:= 0 ->
    luhn(Rest, Index + 1, Sum + D);
luhn([D | Rest], Index, Sum) when D * 2 > 9 ->
    luhn(Rest, Index + 1, Sum + D * 2 - 9);
luhn([D | Rest], Index, Sum) ->
    luhn(Rest, Index + 1, Sum + D * 2).

-doc "The decimal digits of a binary as integers, ignoring separators.".
-spec digits(binary()) -> [0..9].
digits(Binary) ->
    [C - $0 || <<C>> <= Binary, C >= $0, C =< $9].
