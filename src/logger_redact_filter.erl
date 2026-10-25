-module(logger_redact_filter).
-moduledoc ~"""
The primary filter. Installed by `logger_redact:install/1`, or directly in
`sys.config` so it runs from the first event:

```erlang
{kernel, [{logger, [{filters, log, [{logger_redact, {fun logger_redact_filter:filter/2, []}}]}]}]}
```

Before the application has started, the default policy applies.
""".

-export([filter/2]).

-define(SAFE_META_KEYS, [time, pid, gl, mfa, file, line, domain]).

%% OTP removes a primary filter that crashes or returns a malformed event, and
%% passes the original event on unredacted. Every failure therefore ends in a
%% fixed safe event instead, and the reason is left out because it can carry
%% the very data being redacted.
-spec filter(logger:log_event(), term()) -> logger:filter_return().
filter(#{level := Level, meta := Meta} = Event, _Arg) when is_atom(Level), is_map(Meta) ->
    try logger_redact_event:redact(Event, logger_redact_policy:current()) of
        #{msg := Msg, meta := RedactedMeta} = Redacted when is_map(RedactedMeta) ->
            case is_msg(Msg) of
                true -> Redacted;
                false -> safe_event(Level, invalid_msg, Meta)
            end
    catch
        Class:_ -> safe_event(Level, Class, Meta)
    end;
filter(_Event, _Arg) ->
    stop.

safe_event(Level, Error, Meta) ->
    #{
        level => Level,
        msg => {report, #{logger_redact => failed, error => Error}},
        meta => maps:with(?SAFE_META_KEYS, Meta)
    }.

is_msg({report, Report}) when is_map(Report) -> true;
is_msg({report, [Head | _]}) when is_tuple(Head) -> true;
is_msg({string, String}) when is_list(String); is_binary(String) -> true;
is_msg({Format, Args}) when
    (is_list(Format) orelse is_binary(Format) orelse is_atom(Format)), is_list(Args)
->
    true;
is_msg(_) ->
    false.
