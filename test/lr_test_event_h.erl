-module(lr_test_event_h).
-behaviour(gen_event).

-export([init/1, handle_event/2, handle_call/2, format_status/1]).

init(State) ->
    {ok, State}.

handle_event({boom, _Payload}, _State) ->
    error(boom).

handle_call(ping, State) ->
    {ok, pong, State}.

format_status(#{state := #{format_status := crash}}) ->
    error(format_status_crashed);
format_status(Status) ->
    Status.
