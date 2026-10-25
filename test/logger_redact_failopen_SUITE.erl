-module(logger_redact_failopen_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("kernel/include/logger.hrl").

-export([
    all/0,
    init_per_testcase/2,
    end_per_testcase/2,
    crashing_filter/2,
    bad_return_filter/2,
    passthrough_filter/2,
    stock_crashing_filter_is_removed_and_event_passes_raw/1,
    stock_bad_return_is_removed_and_event_passes_raw/1,
    add_primary_filter_prepends/1,
    missing_policy_falls_back_to_defaults/1,
    redactor_survives_invalid_utf8_key/1,
    assert_installed_detects_displacement/1,
    crashing_detector_emits_safe_event/1,
    malformed_event_is_stopped/1,
    env_key_provider/1
]).

all() ->
    [
        stock_crashing_filter_is_removed_and_event_passes_raw,
        stock_bad_return_is_removed_and_event_passes_raw,
        add_primary_filter_prepends,
        missing_policy_falls_back_to_defaults,
        redactor_survives_invalid_utf8_key,
        assert_installed_detects_displacement,
        crashing_detector_emits_safe_event,
        malformed_event_is_stopped,
        env_key_provider
    ].

init_per_testcase(_Case, Config) ->
    #{level := Level} = logger:get_primary_config(),
    ok = logger:set_primary_config(level, debug),
    ok = lr_capture_h:start(),
    [{primary_level, Level} | Config].

end_per_testcase(_Case, Config) ->
    _ = lr_capture_h:stop(),
    _ = logger:remove_primary_filter(crashing),
    _ = logger:remove_primary_filter(bad_return),
    _ = logger:remove_primary_filter(other),
    logger_redact:uninstall(),
    logger:set_primary_config(level, ?config(primary_level, Config)).

crashing_filter(_Event, _Args) ->
    error(boom).

bad_return_filter(_Event, _Args) ->
    not_an_event.

passthrough_filter(_Event, _Args) ->
    ignore.

stock_crashing_filter_is_removed_and_event_passes_raw(_Config) ->
    ok = logger:add_primary_filter(crashing, {fun ?MODULE:crashing_filter/2, []}),
    Canary = ~"canary-crashing-filter",
    ?LOG_ERROR(#{note => Canary}),
    removed_and_leaked(crashing, Canary).

stock_bad_return_is_removed_and_event_passes_raw(_Config) ->
    ok = logger:add_primary_filter(bad_return, {fun ?MODULE:bad_return_filter/2, []}),
    Canary = ~"canary-bad-return",
    ?LOG_ERROR(#{note => Canary}),
    removed_and_leaked(bad_return, Canary).

removed_and_leaked(FilterId, Canary) ->
    Events = lr_capture_h:collect(200),
    #{filters := Filters} = logger:get_primary_config(),
    false = lists:keymember(FilterId, 1, Filters),
    Raw = [E || #{msg := {report, #{note := C}}} = E <- Events, C =:= Canary],
    Debug = [E || #{msg := {report, [{logger, removed_failing_filter} | _]}} = E <- Events],
    ct:log("raw: ~p~ndebug: ~p", [Raw, Debug]),
    [_] = Raw,
    [_] = Debug,
    ok.

add_primary_filter_prepends(_Config) ->
    ok = logger_redact:install(),
    ok = logger:add_primary_filter(other, {fun ?MODULE:passthrough_filter/2, []}),
    #{filters := [{other, _}, {logger_redact, _} | _]} = logger:get_primary_config(),
    ok.

missing_policy_falls_back_to_defaults(_Config) ->
    ok = logger_redact:install(),
    _ = persistent_term:erase({logger_redact, policy}),
    Canary = ~"canary-missing-policy",
    ?LOG_ERROR(#{password => Canary}),
    survived(Canary).

redactor_survives_invalid_utf8_key(_Config) ->
    ok = logger_redact:install(),
    Canary = ~"canary-invalid-utf8",
    ?LOG_ERROR(#{<<255, 254>> => Canary}),
    Events = lr_capture_h:collect(200),
    ok = logger_redact:assert_installed(),
    [] = [E || #{msg := {report, [{logger, removed_failing_filter} | _]}} = E <- Events],
    ct:log("~p", [Events]),
    ok.

survived(Canary) ->
    Events = lr_capture_h:collect(200),
    ok = logger_redact:assert_installed(),
    [] = [E || E <- Events, binary:match(term_to_binary(E), Canary) =/= nomatch],
    [] = [E || #{msg := {report, [{logger, removed_failing_filter} | _]}} = E <- Events],
    ct:log("~p", [Events]),
    ok.

assert_installed_detects_displacement(_Config) ->
    {error, not_installed} = logger_redact:assert_installed(),
    ok = logger_redact:install(),
    ok = logger_redact:assert_installed(),
    ok = logger:add_primary_filter(other, {fun ?MODULE:passthrough_filter/2, []}),
    {error, not_first} = logger_redact:assert_installed(),
    ok = logger_redact:install(),
    ok = logger_redact:assert_installed().

crashing_detector_emits_safe_event(_Config) ->
    ok = logger_redact:install(#{detectors => [{lr_test_detector, #{mode => crash}}]}),
    Canary = ~"canary-TCK-12345678",
    ?LOG_ERROR(#{note => Canary}),
    Events = lr_capture_h:collect(200),
    ok = logger_redact:assert_installed(),
    [#{msg := {report, #{logger_redact := failed, error := error}}, meta := Meta}] = Events,
    [] = maps:keys(maps:without([time, pid, gl, mfa, file, line, domain], Meta)),
    survived(Canary, Events).

malformed_event_is_stopped(_Config) ->
    stop = apply(logger_redact_filter, filter, [#{level => error}, []]),
    stop = apply(logger_redact_filter, filter, [not_an_event, []]),
    #{msg := {report, #{logger_redact := failed}}} =
        apply(logger_redact_filter, filter, [#{level => error, msg => bogus, meta => #{}}, []]).

env_key_provider(_Config) ->
    Name = "LOGGER_REDACT_TEST_KEY",
    {error, not_set} = logger_redact_key_env:load(#{env => Name}),
    true = os:putenv(Name, binary_to_list(binary:copy(~"k", 32))),
    try
        {ok, ~"k1", _} = logger_redact_key_env:load(#{env => Name}),
        ok = logger_redact:install(#{
            hmac => #{key_provider => {logger_redact_key_env, #{env => Name}}}
        }),
        #{email := <<"[email:k1:", _/binary>>} = logger_redact:redact(#{email => ~"a@b.se"})
    after
        os:unsetenv(Name)
    end.

survived(Canary, Events) ->
    [] = [E || E <- Events, binary:match(term_to_binary(E), Canary) =/= nomatch],
    ok.
