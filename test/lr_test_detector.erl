-module(lr_test_detector).
-behaviour(logger_redact_detector).

-export([init/1, keywords/1, scan/2, class/1]).

init(Opts) -> Opts.
keywords(_State) -> [~"TCK-"].
scan(_Text, #{mode := error}) ->
    error;
scan(_Text, #{mode := crash}) ->
    error(detector_crash);
scan(Text, _State) ->
    [{S, L} || {S, _} <- binary:matches(Text, ~"TCK-"), L <- [12], S + L =< byte_size(Text)].
class(_State) -> ticket.
