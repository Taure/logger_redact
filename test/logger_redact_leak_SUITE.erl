-module(logger_redact_leak_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("kernel/include/logger.hrl").

-export([
    all/0,
    groups/0,
    init_per_group/2,
    end_per_group/2,
    init_per_testcase/2,
    end_per_testcase/2,
    gen_server_state/1,
    gen_server_function_clause/1,
    gen_server_format_status_crash/1,
    gen_statem_format_status_hide/1,
    gen_statem_format_status_crash/1,
    proc_lib_crash/1,
    supervisor_start_args/1,
    function_clause_args/1,
    app_report_key/1,
    app_format_email/1,
    app_string_email/1,
    app_metadata_key/1
]).

%% Every case plants canaries, triggers a log path and returns
%% [{Canary, LeaksWithoutFilter}]. The baseline group asserts the second
%% element, which encodes a claim about stock OTP 28/29 behaviour. The
%% redacted group asserts no canary survives and no report_cb crashed.

all() ->
    [{group, baseline}, {group, redacted}].

groups() ->
    Cases = [
        gen_server_state,
        gen_server_function_clause,
        gen_server_format_status_crash,
        gen_statem_format_status_hide,
        gen_statem_format_status_crash,
        proc_lib_crash,
        supervisor_start_args,
        function_clause_args,
        app_report_key,
        app_format_email,
        app_string_email,
        app_metadata_key
    ],
    [{baseline, [], Cases}, {redacted, [], Cases}].

init_per_group(redacted, Config) ->
    ok = logger_redact:install(),
    Config;
init_per_group(_Group, Config) ->
    Config.

end_per_group(redacted, _Config) ->
    logger_redact:uninstall();
end_per_group(_Group, _Config) ->
    ok.

init_per_testcase(_Case, Config) ->
    process_flag(trap_exit, true),
    ok = lr_capture_h:start(),
    Config.

end_per_testcase(_Case, _Config) ->
    _ = lr_capture_h:stop(),
    ok.

gen_server_state(Config) ->
    State = ~"canary-gs-state",
    Message = ~"canary-gs-message",
    {ok, Pid} = lr_test_server:start(#{note => State}),
    gen_server:cast(Pid, {boom, Message}),
    check(Config, await(Pid), [{State, true}, {Message, true}]).

gen_server_function_clause(Config) ->
    State = ~"canary-gsfc-state",
    Message = ~"canary-gsfc-message",
    {ok, Pid} = lr_test_server:start(#{note => State}),
    try gen_server:call(Pid, {unknown, Message}) of
        _ -> ct:fail(expected_crash)
    catch
        exit:_ -> ok
    end,
    check(Config, await(Pid), [{State, true}, {Message, true}]).

gen_server_format_status_crash(Config) ->
    State = ~"canary-gsfs-state",
    Message = ~"canary-gsfs-message",
    {ok, Pid} = lr_test_server:start(#{note => State, format_status => crash}),
    gen_server:cast(Pid, {boom, Message}),
    check(Config, await(Pid), [{State, false}, {Message, true}]).

gen_statem_format_status_hide(Config) ->
    Data = ~"canary-gsmh-data",
    {ok, Pid} = lr_test_statem:start(#{note => Data, format_status => hide}),
    gen_statem:cast(Pid, {boom, ok}),
    check(Config, await(Pid), [{Data, false}]).

gen_statem_format_status_crash(Config) ->
    Data = ~"canary-gsmc-data",
    {ok, Pid} = lr_test_statem:start(#{note => Data, format_status => crash}),
    gen_statem:cast(Pid, {boom, ok}),
    check(Config, await(Pid), [{Data, true}]).

proc_lib_crash(Config) ->
    Dictionary = ~"canary-pl-dictionary",
    Mailbox = ~"canary-pl-mailbox",
    Pid = proc_lib:spawn(fun() ->
        put(note, Dictionary),
        self() ! {pending, Mailbox},
        error(boom)
    end),
    check(Config, await(Pid), [{Dictionary, true}, {Mailbox, true}]).

supervisor_start_args(Config) ->
    Arg = ~"canary-sup-arg",
    {error, _} = supervisor:start_link(lr_test_sup, #{note => Arg}),
    check(Config, lr_capture_h:collect(300), [{Arg, true}]).

function_clause_args(Config) ->
    Arg = ~"canary-fc-arg",
    Pid = proc_lib:spawn(fun() -> lr_test_fun:only_ok(#{note => Arg}) end),
    check(Config, await(Pid), [{Arg, true}]).

app_report_key(Config) ->
    Secret = ~"canary-app-password",
    ?LOG_ERROR(#{what => login_failed, password => Secret}),
    check(Config, lr_capture_h:collect(100), [{Secret, true}]).

app_format_email(Config) ->
    Email = ~"canary.format@example.se",
    ?LOG_ERROR("login failed for ~s", [Email]),
    check(Config, lr_capture_h:collect(100), [{Email, true}]).

app_string_email(Config) ->
    Email = ~"canary.string@example.se",
    logger:error("login failed for canary.string@example.se"),
    check(Config, lr_capture_h:collect(100), [{Email, true}]).

app_metadata_key(Config) ->
    Token = ~"canary-meta-token",
    ?LOG_ERROR(#{what => request}, #{access_token => Token}),
    check(Config, lr_capture_h:collect(100), [{Token, true}]).

await(Pid) ->
    Ref = monitor(process, Pid),
    receive
        {'DOWN', Ref, process, Pid, _} -> ok
    after 2000 -> ct:fail(no_exit)
    end,
    lr_capture_h:collect(300).

check(Config, Events, Expectations) ->
    [] =/= Events orelse ct:fail(no_events),
    Group = proplists:get_value(name, ?config(tc_group_properties, Config)),
    Results = [{Canary, Expected, leaked(Canary, Events)} || {Canary, Expected} <- Expectations],
    ct:log("~p~n~p", [Results, [formatted(E) || E <- Events]]),
    case Group of
        baseline ->
            [] = [R || {_, Expected, Leaked} = R <- Results, Expected =/= Leaked];
        redacted ->
            [] = [R || {_, _, true} = R <- Results],
            [] = [F || E <- Events, F <- [formatted(E)], binary:match(F, ~"CRASH") =/= nomatch]
    end,
    ok.

leaked(Canary, Events) ->
    lists:any(
        fun(Event) ->
            binary:match(term_to_binary(Event), Canary) =/= nomatch orelse
                binary:match(formatted(Event), Canary) =/= nomatch
        end,
        Events
    ).

formatted(Event) ->
    unicode:characters_to_binary(logger_formatter:format(Event, #{single_line => false})).
