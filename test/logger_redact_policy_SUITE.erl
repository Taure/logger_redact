-module(logger_redact_policy_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("kernel/include/logger.hrl").

-export([
    all/0,
    end_per_testcase/2,
    deny_keys_in_every_form/1,
    stems_catch_compound_keys/1,
    allow_keys_skip_scanning/1,
    key_class_without_hmac_key_drops/1,
    key_class_with_hmac_key_pseudonymises/1,
    pseudonyms_are_class_scoped_and_stable/1,
    detected_text_is_pseudonymised/1,
    short_key_is_rejected/1,
    failing_key_provider_installs_with_drop/1,
    classify_marker_at_any_depth/1,
    keep_action_walks_value/1,
    nested_limits/1,
    format_status_helper/1,
    format_status_helper_never_raises/1,
    formatter_wrapper_redacts/1,
    formatter_wrapper_survives_inner_crash/1,
    formatter_check_config/1,
    random_canaries_never_survive/1
]).

-define(KEY, binary:copy(~"k", 32)).

all() ->
    [
        deny_keys_in_every_form,
        stems_catch_compound_keys,
        allow_keys_skip_scanning,
        key_class_without_hmac_key_drops,
        key_class_with_hmac_key_pseudonymises,
        pseudonyms_are_class_scoped_and_stable,
        detected_text_is_pseudonymised,
        short_key_is_rejected,
        failing_key_provider_installs_with_drop,
        classify_marker_at_any_depth,
        keep_action_walks_value,
        nested_limits,
        format_status_helper,
        format_status_helper_never_raises,
        formatter_wrapper_redacts,
        formatter_wrapper_survives_inner_crash,
        formatter_check_config,
        random_canaries_never_survive
    ].

end_per_testcase(_Case, _Config) ->
    logger_redact:uninstall().

deny_keys_in_every_form(_Config) ->
    ok = logger_redact:install(),
    Out = logger_redact:redact(#{
        password => ~"c1", ~"Password" => ~"c2", "API-Key" => ~"c3", [{x_api_key, ~"c4"}] => ok
    }),
    no_canaries(Out, [~"c1", ~"c2", ~"c3", ~"c4"]).

stems_catch_compound_keys(_Config) ->
    ok = logger_redact:install(),
    #{
        db_password_hash := ~"[REDACTED:secret]",
        user_refresh_token_v2 := ~"[REDACTED:secret]",
        name := ~"ok"
    } =
        logger_redact:redact(#{
            db_password_hash => ~"c", user_refresh_token_v2 => ~"c", name => ~"ok"
        }).

allow_keys_skip_scanning(_Config) ->
    ok = logger_redact:install(#{allow_keys => [trace_id]}),
    #{trace_id := ~"a@b.se", other := ~"[REDACTED:email]"} =
        logger_redact:redact(#{trace_id => ~"a@b.se", other => ~"a@b.se"}).

key_class_without_hmac_key_drops(_Config) ->
    ok = logger_redact:install(),
    #{email := ~"[REDACTED:email]", phone := ~"[REDACTED:phone]", msisdn := ~"[REDACTED:phone]"} =
        logger_redact:redact(#{email => "anna@example.se", phone => 46701234567, msisdn => ~"4670"}).

key_class_with_hmac_key_pseudonymises(_Config) ->
    ok = logger_redact:install(hmac(#{})),
    #{email := <<"[email:t1:", Hex:20/binary, "]">>, address := ~"[REDACTED:email]"} =
        logger_redact:redact(#{
            email => ~"anna@example.se", address => logger_redact:classify(email, #{a => 1})
        }),
    {ok, _} = {ok, binary:decode_hex(Hex)}.

pseudonyms_are_class_scoped_and_stable(_Config) ->
    ok = logger_redact:install(hmac(#{actions => #{device_id => hmac}})),
    #{email := A} = logger_redact:redact(#{email => ~"same"}),
    #{email := A} = logger_redact:redact(#{email => ~"same"}),
    #{device_id := B} = logger_redact:redact(#{device_id => ~"same"}),
    <<"[email:t1:", HexA/binary>> = A,
    <<"[device_id:t1:", HexB/binary>> = B,
    true = HexA =/= HexB.

detected_text_is_pseudonymised(_Config) ->
    ok = logger_redact:install(hmac(#{})),
    <<"invite [email:t1:", _:20/binary, "] sent">> = logger_redact:redact(
        ~"invite anna@example.se sent"
    ).

short_key_is_rejected(_Config) ->
    {error, invalid_key} = logger_redact_key:load({lr_test_key, #{key => ~"short"}}).

failing_key_provider_installs_with_drop(_Config) ->
    ok = logger_redact:install(#{hmac => #{key_provider => {lr_test_key, #{fail => vault_down}}}}),
    ok = logger_redact:assert_installed(),
    #{email := ~"[REDACTED:email]"} = logger_redact:redact(#{email => ~"anna@example.se"}).

classify_marker_at_any_depth(_Config) ->
    ok = logger_redact:install(),
    Out = logger_redact:redact([
        {to, #{list => [logger_redact:classify(email, ~"canary-x")]}},
        logger_redact:sensitive(~"canary-y")
    ]),
    no_canaries(Out, [~"canary-x", ~"canary-y"]).

keep_action_walks_value(_Config) ->
    ok = logger_redact:install(#{actions => #{ip => keep}}),
    #{ip := ~"10.0.0.1", remote_addr := #{password := ~"[REDACTED:secret]"}} =
        logger_redact:redact(#{ip => ~"10.0.0.1", remote_addr => #{password => ~"x"}}).

nested_limits(_Config) ->
    ok = logger_redact:install(#{max_depth => 3, max_elements => 5}),
    Deep = #{a => #{b => #{c => #{d => ~"canary-deep"}}}},
    no_canaries(logger_redact:redact(Deep), [~"canary-deep"]),
    Long = lists:duplicate(10, ~"x") ++ [~"canary-long"],
    no_canaries(logger_redact:redact(Long), [~"canary-long"]),
    Improper = improper(~"a", ~"canary-tail@example.se"),
    no_canaries(logger_redact:redact(Improper), [~"canary-tail@example.se"]).

format_status_helper(_Config) ->
    ok = logger_redact:install(),
    Server = logger_redact:format_status(
        #{
            state => #{phase => ready, secret_note => ~"c1"},
            message => {cast, {set, ~"c2"}},
            reason => {bad, #{password => ~"c3"}},
            log => [{in, ~"c4"}]
        },
        #{keep => [phase]}
    ),
    #{state := #{phase := ready}, message := {cast, _}} = Server,
    no_canaries(Server, [~"c1", ~"c2", ~"c3", ~"c4"]),
    Statem = logger_redact:format_status(#{
        state => idle,
        data => {data, ~"c5"},
        queue => [{cast, ~"c6"}],
        postponed => [],
        timeouts => {0, []}
    }),
    #{state := idle, timeouts := {_, _}} = Statem,
    no_canaries(Statem, [~"c5", ~"c6"]).

format_status_helper_never_raises(_Config) ->
    ok = logger_redact:install(),
    persistent_term:put({logger_redact, policy}, broken),
    #{state := ~"[REDACTED]"} = logger_redact:format_status(#{state => #{x => ~"c"}}, #{keep => [x]}),
    ok.

formatter_wrapper_redacts(_Config) ->
    Event = #{
        level => info,
        msg => {report, #{password => ~"canary-fmt"}},
        meta => #{time => logger:timestamp()}
    },
    Out = to_binary(logger_redact_formatter:format(Event, #{formatter => {logger_formatter, #{}}})),
    nomatch = binary:match(Out, ~"canary-fmt"),
    {_, _} = binary:match(Out, ~"[REDACTED:secret]").

formatter_wrapper_survives_inner_crash(_Config) ->
    Event = #{level => info, msg => {string, ~"x"}, meta => #{}},
    ~"logger_redact: formatter failed\n" =
        logger_redact_formatter:format(Event, #{formatter => {lr_no_such_formatter, #{}}}).

formatter_check_config(_Config) ->
    ok = logger_redact_formatter:check_config(#{
        formatter => {logger_formatter, #{single_line => true}}
    }),
    {error, _} = logger_redact_formatter:check_config(#{
        formatter => {logger_formatter, #{single_line => perhaps}}
    }),
    {error, _} = logger_redact_formatter:check_config(#{formatter => nope}),
    {error, {formatter, lr_no_such_formatter, _}} =
        logger_redact_formatter:check_config(#{formatter => {lr_no_such_formatter, #{}}}).

random_canaries_never_survive(_Config) ->
    ok = logger_redact:install(),
    ok = lr_capture_h:start(),
    Seed = rand:seed(exsss),
    ct:log("seed ~p", [Seed]),
    try
        [plant_and_log(N) || N <- lists:seq(1, 300)],
        Events = lr_capture_h:collect(300),
        300 = length(Events),
        Leaks = [E || E <- Events, leaked(E)],
        [] = Leaks
    after
        lr_capture_h:stop()
    end.

plant_and_log(N) ->
    Canary = canary(N),
    case rand:uniform(3) of
        1 -> ?LOG_ERROR(#{what => test, data => nest(Canary, rand:uniform(6))});
        2 -> ?LOG_ERROR("value ~p", [nest(Canary, rand:uniform(6))]);
        3 -> ?LOG_ERROR(#{what => test}, #{extra => nest(Canary, rand:uniform(4))})
    end.

canary(N) ->
    Id = integer_to_binary(N),
    case rand:uniform(5) of
        1 -> {password, <<"canary-", Id/binary>>};
        2 -> {note, <<"canary", Id/binary, "@example.se">>};
        3 -> {note, logger_redact:sensitive(<<"canary-", Id/binary>>)};
        4 -> {note, <<"pay 4111 1111 1111 1111">>};
        5 -> {token, binary_to_list(<<"canary-", Id/binary>>)}
    end.

nest({Key, Value}, 0) ->
    #{Key => Value};
nest(Canary, Depth) ->
    Inner = nest(Canary, Depth - 1),
    case rand:uniform(4) of
        1 -> #{level => Inner};
        2 -> [ok, Inner];
        3 -> {wrap, Inner};
        4 -> [{inner, Inner}]
    end.

leaked(Event) ->
    Patterns = [~"canary", ~"1111 1111"],
    binary:match(term_to_binary(Event), Patterns) =/= nomatch orelse
        binary:match(to_binary(logger_formatter:format(Event, #{})), Patterns) =/= nomatch.

to_binary(Chardata) ->
    case unicode:characters_to_binary(Chardata) of
        Binary when is_binary(Binary) -> Binary
    end.

-spec improper(term(), dynamic()) -> dynamic().
improper(Head, Tail) ->
    [Head | Tail].

hmac(Config) ->
    Config#{hmac => #{key_provider => {lr_test_key, #{key => ?KEY}}}}.

no_canaries(Term, Canaries) ->
    Bin = term_to_binary(Term),
    [] = [C || C <- Canaries, binary:match(Bin, C) =/= nomatch],
    ok.
