-module(logger_redact_sup).
-moduledoc false.
-behaviour(supervisor).

-export([start_link/1, init/1]).

start_link(Interval) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, Interval).

init(Interval) ->
    Guard = #{id => logger_redact_guard, start => {logger_redact_guard, start_link, [Interval]}},
    {ok, {#{strategy => one_for_one, intensity => 10, period => 10}, [Guard]}}.
