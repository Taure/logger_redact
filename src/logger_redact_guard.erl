-module(logger_redact_guard).
-moduledoc ~"""
Keeps the filter first in the primary filter list. Every `guard_interval`
milliseconds it checks the placement, puts the filter back if another filter
was prepended or the filter was removed, and logs an alert.
""".
-behaviour(gen_server).

-include_lib("kernel/include/logger.hrl").

-export([start_link/1, check/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-spec start_link(pos_integer()) -> gen_server:start_ret().
start_link(Interval) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Interval, []).

-doc "Runs a check now. Returns what was found before any repair.".
-spec check() -> ok | {error, not_installed | not_first}.
check() ->
    case gen_server:call(?MODULE, check) of
        ok -> ok;
        {error, not_installed} -> {error, not_installed};
        {error, not_first} -> {error, not_first}
    end.

init(Interval) ->
    {ok, schedule(#{interval => Interval})}.

handle_call(check, _From, State) ->
    {reply, repair(), State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info(check, State) ->
    _ = repair(),
    {noreply, schedule(State)};
handle_info(_Info, State) ->
    {noreply, State}.

repair() ->
    case logger_redact:assert_installed() of
        ok ->
            ok;
        {error, Reason} = Error ->
            ok = logger_redact:place(),
            ?LOG_ALERT(#{what => logger_redact_reinstalled, reason => Reason}),
            Error
    end.

schedule(#{interval := Interval} = State) ->
    erlang:send_after(Interval, self(), check),
    State.
