-module(logger_redact_detect_SUITE).

-include_lib("common_test/include/ct.hrl").

-export([
    all/0,
    end_per_testcase/2,
    init_per_testcase/2,
    email/1,
    jwt/1,
    bearer_keeps_scheme/1,
    pem_block/1,
    pem_truncated/1,
    url_userinfo/1,
    api_keys/1,
    pan_requires_luhn/1,
    iban_requires_mod97/1,
    personnummer_requires_date_and_luhn/1,
    phone_international/1,
    ip_is_opt_in/1,
    clean_text_is_untouched/1,
    overlapping_matches/1,
    oversize_binary_is_truncated/1,
    match_limit_redacts_whole_binary/1,
    detector_error_redacts_whole_binary/1,
    custom_detector/1,
    charlist_and_format_args/1
]).

all() ->
    [
        email,
        jwt,
        bearer_keeps_scheme,
        pem_block,
        pem_truncated,
        url_userinfo,
        api_keys,
        pan_requires_luhn,
        iban_requires_mod97,
        personnummer_requires_date_and_luhn,
        phone_international,
        ip_is_opt_in,
        clean_text_is_untouched,
        overlapping_matches,
        oversize_binary_is_truncated,
        match_limit_redacts_whole_binary,
        detector_error_redacts_whole_binary,
        custom_detector,
        charlist_and_format_args
    ].

end_per_testcase(_Case, _Config) ->
    logger_redact:uninstall().

init_per_testcase(_Case, Config) ->
    ok = logger_redact:install(#{actions => #{email => drop, phone => drop, ip => drop}}),
    Config.

email(_Config) ->
    ~"to [REDACTED:email] and [REDACTED:email]." = r(~"to anna.b+tag@example.se and x@y.co."),
    ~"user@localhost" = r(~"user@localhost").

jwt(_Config) ->
    ~"t=[REDACTED:credential];" = r(~"t=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2ln;").

bearer_keeps_scheme(_Config) ->
    ~"Authorization: Bearer [REDACTED:credential]" = r(~"Authorization: Bearer abc.def-123_456"),
    ~"basic [REDACTED:credential]" = r(~"basic dXNlcjpwYXNzd29yZA=="),
    ~"bearer short" = r(~"bearer short").

pem_block(_Config) ->
    Pem = ~"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----",
    ~"key [REDACTED:secret] done" = r(<<"key ", Pem/binary, " done">>),
    Cert = ~"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
    true = Cert =:= r(Cert).

pem_truncated(_Config) ->
    ~"x [REDACTED:secret]" = r(~"x -----BEGIN EC PRIVATE KEY-----\nMHcCAQEE").

url_userinfo(_Config) ->
    ~"postgres://[REDACTED:secret]@db:5432/app" = r(~"postgres://app:hunter2@db:5432/app"),
    ~"https://example.se/a:b@c" = r(~"https://example.se/a:b@c").

api_keys(_Config) ->
    Keys = [
        ~"AKIAIOSFODNN7EXAMPLE",
        <<"ghp_", (binary:copy(~"a", 36))/binary>>,
        <<"github_pat_", (binary:copy(~"B", 30))/binary>>,
        <<"sk_live_", (binary:copy(~"9", 24))/binary>>,
        ~"xoxb-1234567890-abcdef"
    ],
    [~"k=[REDACTED:secret]" = r(<<"k=", K/binary>>) || K <- Keys],
    ~"AKIA short" = r(~"AKIA short").

pan_requires_luhn(_Config) ->
    ~"[REDACTED:pan]" = r(~"4111111111111111"),
    ~"[REDACTED:pan] ok" = r(~"5555-5555-5555-4444 ok"),
    ~"4111111111111112" = r(~"4111111111111112"),
    ~"order 1234567890123" = r(~"order 1234567890123").

iban_requires_mod97(_Config) ->
    ~"[REDACTED:iban]" = r(~"SE45 5000 0000 0583 9825 7466"),
    ~"[REDACTED:iban]" = r(~"GB82WEST12345698765432"),
    ~"SE45 5000 0000 0583 9825 7467" = r(~"SE45 5000 0000 0583 9825 7467").

personnummer_requires_date_and_luhn(_Config) ->
    ~"[REDACTED:national_id]" = r(~"19121212-1212"),
    ~"[REDACTED:national_id]" = r(~"121212-1212"),
    ~"[REDACTED:national_id]" = r(~"191212121212"),
    ~"121212-1213" = r(~"121212-1213"),
    ~"121312-1212" = r(~"121312-1212").

phone_international(_Config) ->
    ~"call [REDACTED:phone] now" = r(~"call +46 70 123 45 67 now"),
    ~"[REDACTED:phone]" = r(~"+4670-1234567"),
    ~"070-123 45 67" = r(~"070-123 45 67"),
    ~"1+1=2" = r(~"1+1=2").

ip_is_opt_in(_Config) ->
    ~"from 10.1.2.3" = r(~"from 10.1.2.3"),
    ok = logger_redact:install(#{
        detectors => [logger_redact_detect_ip], actions => #{ip => drop}
    }),
    ~"from [REDACTED:ip] and [REDACTED:ip]" = r(~"from 10.1.2.3 and 2001:db8::1"),
    ~"[REDACTED:ip] [REDACTED:ip]" = r(~"fe80::1 2001:db8:0:0:0:0:0:1"),
    ~"v1.2.3 999.1.1.1 at 12:30:45 Mod::fun" = r(~"v1.2.3 999.1.1.1 at 12:30:45 Mod::fun").

clean_text_is_untouched(_Config) ->
    Texts = [
        ~"match 0192c3a4-5b6c-7d8e-9f01-23456789abcd ended at 1729850000123",
        ~"tick 42 took 1.25 ms on node asobi@host",
        ~"version 29.1.2 build 20261025"
    ],
    [] = [T || T <- Texts, r(T) =/= T],
    ok.

overlapping_matches(_Config) ->
    ~"redis://[REDACTED:secret]@cache" = r(~"redis://admin:pw@example.se@cache").

oversize_binary_is_truncated(_Config) ->
    ok = logger_redact:install(#{max_scan_bytes => 32}),
    Text = <<"a@b.se ", (binary:copy(~"x", 100))/binary, " tail@example.se">>,
    Out = r(Text),
    nomatch = binary:match(Out, ~"@"),
    {_, _} = binary:match(Out, ~"[TRUNCATED bytes="),
    Utf8 = binary:copy(~"ö", 40),
    <<_/binary>> = unicode:characters_to_binary(r(Utf8)).

match_limit_redacts_whole_binary(_Config) ->
    ok = logger_redact:install(#{match_limit => 1}),
    ~"[REDACTED:email]" = r(~"contact anna@example.se").

detector_error_redacts_whole_binary(_Config) ->
    ok = logger_redact:install(#{detectors => [{lr_test_detector, #{mode => error}}]}),
    ~"[REDACTED:ticket]" = r(~"see TCK-12345678"),
    ~"no anchor" = r(~"no anchor").

custom_detector(_Config) ->
    ok = logger_redact:install(#{detectors => [{lr_test_detector, #{}}]}),
    ~"see [REDACTED:ticket] ok" = r(~"see TCK-12345678 ok").

charlist_and_format_args(_Config) ->
    ~"[REDACTED:email]" = r("anna@example.se"),
    "plain" = r("plain"),
    [~"[REDACTED:email]", 42, ~"x"] = r([~"anna@example.se", 42, ~"x"]).

r(Term) ->
    logger_redact:redact(Term).
