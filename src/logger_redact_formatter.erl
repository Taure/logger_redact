-module(logger_redact_formatter).
-moduledoc ~"""
Wraps another formatter and redacts each event before it is formatted. Use it
as defence in depth on handlers that write outside the node, or where events
can reach a handler without passing the primary filter.

```erlang
logger:update_handler_config(default, formatter,
    {logger_redact_formatter, #{formatter => {logger_formatter, #{single_line => true}}}})
```

If the inner formatter fails, a fixed line is returned instead, so
`logger_h_common` never falls back to printing the raw event.
""".

-export([format/2, check_config/1]).

-define(FAILED, ~"logger_redact: formatter failed\n").

-spec format(logger:log_event(), map()) -> unicode:chardata().
format(Event, Config) ->
    {Module, Inner} = maps:get(formatter, Config, {logger_formatter, #{}}),
    try
        Module:format(logger_redact_event:redact(Event, logger_redact_policy:current()), Inner)
    catch
        _:_ -> ?FAILED
    end.

-spec check_config(map()) -> ok | {error, term()}.
check_config(#{formatter := {Module, Inner}}) when is_atom(Module), is_map(Inner) ->
    case code:ensure_loaded(Module) of
        {module, Module} ->
            case erlang:function_exported(Module, check_config, 1) of
                true -> Module:check_config(Inner);
                false -> ok
            end;
        {error, Reason} ->
            {error, {formatter, Module, Reason}}
    end;
check_config(#{formatter := Formatter}) ->
    {error, {invalid_formatter, Formatter}};
check_config(Config) when is_map(Config) ->
    ok;
check_config(Config) ->
    {error, {invalid_config, Config}}.
