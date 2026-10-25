-module(lr_test_server).
-behaviour(gen_server).

-export([start/1, init/1, handle_call/3, handle_cast/2, format_status/1]).

start(State) ->
    gen_server:start(?MODULE, State, []).

init(State) ->
    {ok, State}.

handle_call(known, _From, State) ->
    {reply, ok, State}.

handle_cast({boom, _Payload}, _State) ->
    error(boom).

format_status(#{state := #{format_status := crash}}) ->
    error(format_status_crashed);
format_status(#{state := #{format_status := hide}} = Status) ->
    Status#{state := hidden};
format_status(Status) ->
    Status.
