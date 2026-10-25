-module(logger_redact_guard_SUITE).

-include_lib("common_test/include/ct.hrl").

-export([
    all/0,
    init_per_testcase/2,
    end_per_testcase/2,
    passthrough/2,
    crash/2,
    app_start_installs_filter/1,
    guard_restores_after_prepend/1,
    guard_restores_after_removal/1,
    guard_restores_after_otp_removes_filter/1,
    sys_config_filter_uses_default_policy/1
]).

all() ->
    [
        app_start_installs_filter,
        guard_restores_after_prepend,
        guard_restores_after_removal,
        guard_restores_after_otp_removes_filter,
        sys_config_filter_uses_default_policy
    ].

init_per_testcase(sys_config_filter_uses_default_policy, Config) ->
    Config;
init_per_testcase(_Case, Config) ->
    application:set_env(logger_redact, guard_interval, 50),
    {ok, _} = application:ensure_all_started(logger_redact),
    Config.

end_per_testcase(_Case, _Config) ->
    _ = application:stop(logger_redact),
    _ = logger:remove_primary_filter(other),
    application:unset_env(logger_redact, guard_interval),
    logger_redact:uninstall().

passthrough(_Event, _Arg) -> ignore.

crash(_Event, _Arg) -> error(boom).

app_start_installs_filter(_Config) ->
    ok = logger_redact:assert_installed().

guard_restores_after_prepend(_Config) ->
    ok = logger:add_primary_filter(other, {fun ?MODULE:passthrough/2, []}),
    {error, not_first} = logger_redact_guard:check(),
    ok = logger_redact:assert_installed(),
    #{filters := [{logger_redact, _}, {other, _} | _]} = logger:get_primary_config(),
    ok.

guard_restores_after_removal(_Config) ->
    ok = logger:remove_primary_filter(logger_redact),
    ok = await_installed(40).

guard_restores_after_otp_removes_filter(_Config) ->
    ok = logger:update_primary_config(#{filters => [{logger_redact, {fun ?MODULE:crash/2, []}}]}),
    logger:error("trigger"),
    ok = await_installed(40),
    #{filters := [{logger_redact, {Fun, _}} | _]} = logger:get_primary_config(),
    true = Fun =:= fun logger_redact_filter:filter/2.

sys_config_filter_uses_default_policy(_Config) ->
    logger_redact:uninstall(),
    ok = logger:add_primary_filter(logger_redact, {fun logger_redact_filter:filter/2, []}),
    ok = lr_capture_h:start(),
    try
        logger:error(#{password => ~"canary-boot"}),
        [Event] = lr_capture_h:collect(200),
        nomatch = binary:match(term_to_binary(Event), ~"canary-boot")
    after
        lr_capture_h:stop()
    end.

await_installed(0) ->
    {error, timeout};
await_installed(N) ->
    case logger_redact:assert_installed() of
        ok -> ok;
        _ -> receive
            after 25 -> await_installed(N - 1)
            end
    end.
