-module(logger_redact_event).

-moduledoc false.

-export([redact/2, term/2, summarise/1]).

-define(MARKER, '$logger_redact').
-define(REDACTED, ~"[REDACTED]").
-define(TRUNCATED, ~"[TRUNCATED]").
-define(META_PASSTHROUGH, [
    time, pid, gl, mfa, file, line, domain, report_cb, error_logger, logger_formatter
]).

-spec redact(logger:log_event(), logger_redact_policy:policy()) -> logger:log_event().
redact(#{msg := Msg, meta := Meta} = Event, Policy) ->
    Ctx = Policy#{otp := is_otp(Meta)},
    Event#{msg := msg(Msg, Ctx), meta := meta(Meta, Policy)}.

-spec term(term(), logger_redact_policy:policy()) -> term().
term(Term, Policy) ->
    walk(Term, Policy, 0).

is_otp(#{domain := [otp | _]}) -> true;
is_otp(_Meta) -> false.

msg({report, Report}, Ctx) ->
    {report, walk(Report, Ctx, 0)};
msg({string, String}, Ctx) ->
    {string, chardata(String, Ctx)};
msg({Format, Args}, Ctx) when is_list(Args) ->
    {Format, [walk(Arg, Ctx, 1) || Arg <- Args]}.

meta(Meta, Policy) ->
    #{K => meta_value(K, V, Policy) || K := V <- Meta}.

meta_value(Key, Value, Policy) ->
    case lists:member(Key, ?META_PASSTHROUGH) of
        true -> Value;
        false -> pair(Key, Value, Policy, 0)
    end.

walk(_Term, #{max_depth := Max}, Depth) when Depth > Max ->
    ?TRUNCATED;
walk({?MARKER, Class, Value}, Ctx, Depth) when is_atom(Class) ->
    classified(Class, Value, Ctx, Depth);
walk(Map, #{max_elements := Max}, _Depth) when is_map(Map), map_size(Map) > Max ->
    summarise(Map);
walk(Map, Ctx, Depth) when is_map(Map) ->
    #{walk(K, Ctx, Depth + 1) => pair(K, V, Ctx, Depth + 1) || K := V <- Map};
walk([Char | _] = List, Ctx, Depth) when is_integer(Char) ->
    case io_lib:printable_unicode_list(List) of
        true -> charlist(List, Ctx);
        false -> elements(List, Ctx, Depth + 1, 0)
    end;
walk(List, Ctx, Depth) when is_list(List) ->
    elements(List, Ctx, Depth + 1, 0);
walk({Module, Function, Args, Location}, _Ctx, _Depth) when
    is_atom(Module), is_atom(Function), is_list(Args), is_list(Location)
->
    {Module, Function, length(Args), Location};
walk({Key, Value}, Ctx, Depth) ->
    {walk(Key, Ctx, Depth + 1), pair(Key, Value, Ctx, Depth + 1)};
walk(Tuple, #{max_elements := Max}, _Depth) when is_tuple(Tuple), tuple_size(Tuple) > Max ->
    summarise(Tuple);
walk(Tuple, Ctx, Depth) when is_tuple(Tuple) ->
    list_to_tuple([walk(E, Ctx, Depth + 1) || E <- tuple_to_list(Tuple)]);
walk(Binary, Ctx, _Depth) when is_binary(Binary) ->
    text(Binary, Ctx);
walk(Term, _Ctx, _Depth) ->
    Term.

pair(Key, Value, Ctx, Depth) ->
    case key_action(Key, Ctx) of
        {class, Class} -> classified(Class, Value, Ctx, Depth);
        allow -> Value;
        summarise -> summarise(Value);
        walk -> walk(Value, Ctx, Depth)
    end.

classified(Class, Value, #{actions := Actions} = Ctx, Depth) ->
    case maps:get(Class, Actions, drop) of
        keep ->
            walk(Value, Ctx, Depth);
        _ ->
            case textual(Value) of
                {ok, Text} -> logger_redact_text:replacement(Class, Text, Ctx);
                error -> logger_redact_text:dropped(Class)
            end
    end.

textual(Binary) when is_binary(Binary) ->
    {ok, Binary};
textual(Integer) when is_integer(Integer) ->
    {ok, integer_to_binary(Integer)};
textual([Char | _] = List) when is_integer(Char) ->
    case io_lib:printable_unicode_list(List) of
        true -> {ok, unicode:characters_to_binary(List)};
        false -> error
    end;
textual(_Term) ->
    error.

key_action(Key, #{otp := true, otp_summarise := Otp} = Ctx) when is_atom(Key) ->
    case maps:is_key(Key, Otp) of
        true -> summarise;
        false -> key_rule(Key, Ctx)
    end;
key_action(Key, Ctx) ->
    key_rule(Key, Ctx).

key_rule(Key, Ctx) when is_atom(Key); is_binary(Key) ->
    normalised_rule(logger_redact_policy:normalise_key(Key), Ctx);
key_rule([Char | _] = Key, Ctx) when is_integer(Char) ->
    normalised_rule(logger_redact_policy:normalise_key(Key), Ctx);
key_rule(_Key, _Ctx) ->
    walk.

normalised_rule(undefined, _Ctx) ->
    walk;
normalised_rule(Key, #{keys := Keys, stems := Stems}) ->
    case Keys of
        #{Key := Rule} -> Rule;
        #{} when Stems =/= none -> stem_rule(binary:match(Key, Stems));
        #{} -> walk
    end.

stem_rule(nomatch) -> walk;
stem_rule(_Match) -> {class, secret}.

elements([], _Ctx, _Depth, _Count) ->
    [];
elements(_List, #{max_elements := Max}, _Depth, Count) when Count >= Max ->
    [?TRUNCATED];
elements([Head | Tail], Ctx, Depth, Count) ->
    [walk(Head, Ctx, Depth) | elements(Tail, Ctx, Depth, Count + 1)];
elements(Tail, Ctx, Depth, _Count) ->
    walk(Tail, Ctx, Depth).

%% OTP's report_cb functions pattern match on the shape of these fields (a list
%% they comprehend over, a {StateName, Data} tuple), so a summary keeps the
%% outer shape and record or state names while dropping every value.
-spec summarise(term()) -> term().
summarise(Tuple) when is_tuple(Tuple) ->
    list_to_tuple([marker(E) || E <- tuple_to_list(Tuple)]);
summarise([]) ->
    [];
summarise(List) when is_list(List) ->
    [~"[REDACTED list]"];
summarise(Term) ->
    marker(Term).

marker(Atom) when is_atom(Atom) ->
    Atom;
marker(Map) when is_map(Map) ->
    iolist_to_binary([~"[REDACTED map size=", integer_to_binary(map_size(Map)), ~"]"]);
marker(Tuple) when is_tuple(Tuple) ->
    iolist_to_binary([~"[REDACTED tuple size=", integer_to_binary(tuple_size(Tuple)), ~"]"]);
marker(Binary) when is_binary(Binary) ->
    iolist_to_binary([~"[REDACTED binary size=", integer_to_binary(byte_size(Binary)), ~"]"]);
marker(List) when is_list(List) ->
    ~"[REDACTED list]";
marker(_Term) ->
    ?REDACTED.

chardata(String, Ctx) ->
    case unicode:characters_to_binary(String) of
        Binary when is_binary(Binary) ->
            case text(Binary, Ctx) of
                Binary -> String;
                Redacted -> Redacted
            end;
        _Invalid ->
            ?REDACTED
    end.

charlist(List, Ctx) ->
    Binary = unicode:characters_to_binary(List),
    case text(Binary, Ctx) of
        Binary -> List;
        Redacted -> Redacted
    end.

text(Binary, Ctx) ->
    logger_redact_text:scan(Binary, Ctx).
