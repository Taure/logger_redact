-module(lr_test_key).
-behaviour(logger_redact_key).

-export([load/1]).

load(#{key := Key}) -> {ok, ~"t1", Key};
load(#{fail := Reason}) -> {error, Reason}.
