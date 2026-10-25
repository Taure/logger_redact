-module(logger_redact_bench_SUITE).

-export([all/0, run/1]).

all() ->
    [run].

run(_Config) ->
    logger_redact_bench:run().
