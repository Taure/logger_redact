-module(logger_redact_app).
-moduledoc false.
-behaviour(application).

-export([start/2, stop/1]).

start(_Type, _Args) ->
    case application:get_env(logger_redact, install, true) of
        true -> ok = logger_redact:install(policy_env());
        false -> ok
    end,
    logger_redact_sup:start_link(application:get_env(logger_redact, guard_interval, 1000)).

stop(_State) ->
    ok.

-spec policy_env() -> dynamic().
policy_env() ->
    application:get_env(logger_redact, policy, #{}).
