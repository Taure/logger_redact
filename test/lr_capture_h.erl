-module(lr_capture_h).

-export([start/0, stop/0, collect/1, log/2]).

start() ->
    logger:add_handler(lr_capture, ?MODULE, #{level => all, config => #{owner => self()}}).

stop() ->
    logger:remove_handler(lr_capture).

collect(Timeout) ->
    receive
        {lr_captured, Event} -> [Event | collect(Timeout)]
    after Timeout -> []
    end.

log(Event, #{config := #{owner := Owner}}) ->
    Owner ! {lr_captured, Event},
    ok.
