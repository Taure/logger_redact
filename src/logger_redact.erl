-module(logger_redact).
-moduledoc ~"""
Redacts PII and secrets from OTP `logger` events with a fail-closed primary
filter.

Starting the application installs the filter with the policy from the
`logger_redact` application environment and starts a guard that keeps it
first in the primary filter list. See the [README](readme.html) and the [configuration guide](configuration.html).
""".

-include_lib("kernel/include/logger.hrl").

-export([
    install/0,
    install/1,
    place/0,
    uninstall/0,
    assert_installed/0,
    redact/1,
    classify/2,
    sensitive/1,
    format_status/1,
    format_status/2
]).

-export_type([classified/0]).

-define(FILTER_ID, ?MODULE).
-define(MARKER, '$logger_redact').
-define(SUMMARISED_STATUS, [message, queue, postponed, log, timeouts]).

-opaque classified() :: {?MARKER, atom(), term()}.

-doc #{equiv => install(#{})}.
-spec install() -> ok | {error, term()}.
install() ->
    install(#{}).

-doc """
Compiles `Config`, loads the HMAC key if a provider is configured, and places
the filter first among the primary filters. If the key cannot be loaded the
filter is still installed and `hmac` classes are dropped.
""".
-spec install(logger_redact_policy:config()) -> ok | {error, term()}.
install(Config) ->
    Policy = logger_redact_policy:compile(Config),
    load_key(maps:get(hmac, Config, #{})),
    logger_redact_policy:store(Policy),
    place().

-doc """
Places the filter first in the primary filter list, keeping the stored policy.
`logger:add_primary_filter/2` prepends, so a filter added later would
otherwise run before this one.
""".
-spec place() -> ok | {error, term()}.
place() ->
    #{filters := Filters} = logger:get_primary_config(),
    Ours = {?FILTER_ID, {fun logger_redact_filter:filter/2, []}},
    Others = [Filter || {Id, _} = Filter <- Filters, Id =/= ?FILTER_ID],
    logger:update_primary_config(#{filters => [Ours | Others]}).

-doc "Removes the filter, the policy and the HMAC key.".
-spec uninstall() -> ok.
uninstall() ->
    _ = logger:remove_primary_filter(?FILTER_ID),
    ok = logger_redact_policy:erase(),
    logger_redact_key:erase().

-doc "Checks that the filter is installed and runs first.".
-spec assert_installed() -> ok | {error, not_installed | not_first}.
assert_installed() ->
    case logger:get_primary_config() of
        #{filters := [{?FILTER_ID, _} | _]} ->
            ok;
        #{filters := Filters} ->
            case lists:keymember(?FILTER_ID, 1, Filters) of
                true -> {error, not_first};
                false -> {error, not_installed}
            end
    end.

-doc "Redacts any term with the active policy, for data sent elsewhere than `logger`.".
-spec redact(term()) -> term().
redact(Term) ->
    logger_redact_event:term(Term, logger_redact_policy:current()).

-doc """
Marks a value as belonging to `Class`, for values logged under keys that say
nothing about their content:

```erlang
?LOG_INFO(#{what => invite_sent, to => logger_redact:classify(email, Address)})
```
""".
-spec classify(atom(), term()) -> classified().
classify(Class, Value) when is_atom(Class) ->
    {?MARKER, Class, Value}.

-doc #{equiv => classify(secret, Value)}.
-spec sensitive(term()) -> classified().
sensitive(Value) ->
    classify(secret, Value).

-doc #{equiv => format_status(Status, #{})}.
-spec format_status(map()) -> map().
format_status(Status) ->
    format_status(Status, #{}).

-doc """
A `format_status/1` implementation for gen_server, gen_statem and gen_event
callback modules. Messages, queues and the sys log are summarised, and server
state or data is summarised except for the map keys listed in `keep`. It never
raises, because a crashing `format_status/1` makes OTP log the raw message and
reason.

```erlang
format_status(Status) -> logger_redact:format_status(Status, #{keep => [phase, retries]}).
```
""".
-spec format_status(map(), #{keep => [term()]}) -> map().
format_status(Status, Opts) ->
    try
        Policy = logger_redact_policy:current(),
        Keep = maps:get(keep, Opts, []),
        #{K => status_field(K, V, Status, Keep, Policy) || K := V <- Status}
    catch
        _:_ -> #{K => ~"[REDACTED]" || K := _ <- Status}
    end.

status_field(state, Name, #{data := _}, _Keep, Policy) ->
    logger_redact_event:term(Name, Policy);
status_field(Key, Value, _Status, Keep, Policy) when Key =:= state; Key =:= data ->
    kept(Value, Keep, Policy);
status_field(Key, Value, _Status, _Keep, Policy) ->
    case lists:member(Key, ?SUMMARISED_STATUS) of
        true -> logger_redact_event:summarise(Value);
        false -> logger_redact_event:term(Value, Policy)
    end.

kept(Map, Keep, Policy) when is_map(Map) ->
    #{K => kept_value(lists:member(K, Keep), V, Policy) || K := V <- Map};
kept(Value, _Keep, _Policy) ->
    logger_redact_event:summarise(Value).

kept_value(true, Value, Policy) -> logger_redact_event:term(Value, Policy);
kept_value(false, Value, _Policy) -> logger_redact_event:summarise(Value).

load_key(#{key_provider := Provider}) ->
    case logger_redact_key:load(Provider) of
        ok ->
            ok;
        {error, Reason} ->
            ok = logger_redact_key:erase(),
            ?LOG_WARNING(#{what => logger_redact_key_unavailable, reason => Reason})
    end;
load_key(_Hmac) ->
    ok.
