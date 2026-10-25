-module(lr_test_sup).
-behaviour(supervisor).

-export([init/1, start_child/1]).

init(Arg) ->
    Child = #{id => child, start => {?MODULE, start_child, [Arg]}},
    {ok, {#{strategy => one_for_one, intensity => 0, period => 1}, [Child]}}.

start_child(_Arg) ->
    {error, refused}.
