-module(logger_redact_otp_status_SUITE).

-include_lib("common_test/include/ct.hrl").

-export([
    all/0,
    init_per_testcase/2,
    gen_server_get_status_hides_state/1,
    gen_statem_get_status_hides_data/1,
    gen_event_get_status_leaks_state/1,
    gen_event_terminate_leaks_state/1
]).

%% Stock OTP behaviour when format_status/1 crashes. The documented contract
%% is that state is hidden; each case asserts what OTP actually does.

all() ->
    [
        gen_server_get_status_hides_state,
        gen_statem_get_status_hides_data,
        gen_event_get_status_leaks_state,
        gen_event_terminate_leaks_state
    ].

init_per_testcase(_Case, Config) ->
    process_flag(trap_exit, true),
    Config.

gen_server_get_status_hides_state(_Config) ->
    Canary = ~"canary-sys-gen-server",
    {ok, Pid} = lr_test_server:start(#{note => Canary, format_status => crash}),
    false = contains(sys:get_status(Pid), Canary).

gen_statem_get_status_hides_data(_Config) ->
    Canary = ~"canary-sys-gen-statem",
    {ok, Pid} = lr_test_statem:start(#{note => Canary, format_status => crash}),
    false = contains(sys:get_status(Pid), Canary).

gen_event_get_status_leaks_state(_Config) ->
    Canary = ~"canary-sys-gen-event",
    {ok, Mgr} = gen_event:start(),
    ok = gen_event:add_handler(Mgr, lr_test_event_h, #{note => Canary, format_status => crash}),
    true = contains(sys:get_status(Mgr), Canary).

gen_event_terminate_leaks_state(_Config) ->
    Canary = ~"canary-terminate-gen-event",
    ok = lr_capture_h:start(),
    {ok, Mgr} = gen_event:start(),
    ok = gen_event:add_handler(Mgr, lr_test_event_h, #{note => Canary, format_status => crash}),
    ok = gen_event:notify(Mgr, {boom, ok}),
    Events = lr_capture_h:collect(300),
    _ = lr_capture_h:stop(),
    [Terminate] = [E || #{msg := {report, #{label := {gen_event, terminate}}}} = E <- Events],
    ct:log("~p", [Terminate]),
    true = contains(Terminate, Canary).

contains(Term, Canary) ->
    binary:match(term_to_binary(Term), Canary) =/= nomatch.
