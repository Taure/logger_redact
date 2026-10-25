-module(lr_test_statem).
-behaviour(gen_statem).

-export([start/1, init/1, callback_mode/0, idle/3, format_status/1]).

start(Data) ->
    gen_statem:start(?MODULE, Data, []).

init(Data) ->
    {ok, idle, Data}.

callback_mode() ->
    state_functions.

idle(cast, {boom, _Payload}, _Data) ->
    error(boom).

format_status(#{data := #{format_status := crash}}) ->
    error(format_status_crashed);
format_status(#{data := #{format_status := hide}} = Status) ->
    Status#{data := hidden};
format_status(Status) ->
    Status.
