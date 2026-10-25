-module(logger_redact_bench).

-export([run/0]).

-define(ITERATIONS, 20000).

run() ->
    ok = logger_redact:install(),
    Policy = persistent_term:get({logger_redact, policy}),
    io:format(user, "~-28s ~12s ~12s ~8s~n", [scenario, "filter us", "format us", ratio]),
    [report(Name, Event, Policy) || {Name, Event} <- scenarios()],
    logger_redact:uninstall().

report(Name, Event, Policy) ->
    Filter = per_event(fun() -> logger_redact_filter:filter(Event, {logger_redact, policy}) end),
    Format = per_event(fun() -> logger_formatter:format(Event, #{}) end),
    _ = Policy,
    io:format(user, "~-28s ~12.3f ~12.3f ~8.2f~n", [Name, Filter, Format, Filter / Format]).

per_event(Fun) ->
    _ = [Fun() || _ <- lists:seq(1, 1000)],
    {Micros, _} = timer:tc(fun() -> loop(Fun, ?ITERATIONS) end),
    Micros / ?ITERATIONS.

loop(_Fun, 0) ->
    ok;
loop(Fun, N) ->
    _ = Fun(),
    loop(Fun, N - 1).

scenarios() ->
    LargeState = #{integer_to_binary(N) => #{player => N, score => N * 10} || N <- lists:seq(1, 1000)},
    Players = [#{id => N, name => ~"player", email => ~"player@example.se"} || N <- lists:seq(1, 500)],
    [
        {clean_report, event({report, #{what => request_done, status => 200, path => ~"/api/v1/matches", duration_ms => 12}})},
        {secret_key_report, event({report, #{what => login, user_id => 42, password => ~"hunter2"}})},
        {format_with_email, event({"login failed for ~s from ~s", [~"anna@example.se", ~"10.0.0.1"]})},
        {string_200b_clean, event({string, binary:copy(~"match tick processed ", 10)})},
        {string_with_email, event({string, ~"invite sent to anna@example.se for match 1234"})},
        {gen_server_large_state, otp_event(LargeState)},
        {nested_500_players, event({report, #{what => roster, players => Players}})}
    ].

event(Msg) ->
    #{level => info, msg => Msg, meta => #{time => logger:timestamp(), pid => self(), gl => group_leader()}}.

otp_event(State) ->
    #{
        level => error,
        msg =>
            {report, #{
                label => {gen_server, terminate},
                name => self(),
                last_message => {cast, {boom, ~"payload"}},
                state => State,
                log => [],
                reason => {boom, []},
                client_info => undefined,
                process_label => undefined
            }},
        meta => #{
            time => logger:timestamp(),
            pid => self(),
            gl => group_leader(),
            domain => [otp],
            report_cb => fun gen_server:format_log/2
        }
    }.
