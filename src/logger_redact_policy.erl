-module(logger_redact_policy).
-moduledoc ~"""
Compiles a policy configuration into the form the walker uses, and holds the
active policy in `persistent_term`.

Every key is optional. Omitted keys take the defaults listed in the
[configuration guide](configuration.html).
""".

-export([compile/1, current/0, store/1, erase/0, normalise_key/1, defaults/0]).

-export_type([config/0, policy/0, action/0, class/0]).

-define(PERSISTENT_KEY, {logger_redact, policy}).

-define(DENY_KEYS, [
    password,
    passwd,
    pwd,
    secret,
    client_secret,
    api_key,
    apikey,
    private_key,
    token,
    access_token,
    refresh_token,
    id_token,
    session,
    session_id,
    sid,
    cookie,
    set_cookie,
    authorization,
    proxy_authorization,
    x_api_key,
    otp,
    cvv,
    cvc,
    pin,
    dsn
]).
-define(DENY_STEMS, [~"passw", ~"secret", ~"token", ~"apikey", ~"privatekey", ~"authoriz"]).
-define(KEY_CLASSES, #{
    email => email,
    e_mail => email,
    email_address => email,
    phone => phone,
    phone_number => phone,
    mobile => phone,
    msisdn => phone,
    ip => ip,
    ip_address => ip,
    remote_ip => ip,
    remote_addr => ip,
    client_ip => ip,
    device_id => device_id,
    push_token => device_id,
    personnummer => national_id,
    samordningsnummer => national_id,
    ssn => national_id,
    national_id => national_id,
    card_number => pan,
    pan => pan,
    iban => iban
}).
-define(ACTIONS, #{
    secret => drop,
    credential => drop,
    national_id => drop,
    pan => drop,
    iban => drop,
    email => hmac,
    phone => hmac,
    ip => hmac,
    device_id => hmac
}).
-define(DETECTORS, [
    logger_redact_detect_email,
    logger_redact_detect_jwt,
    logger_redact_detect_bearer,
    logger_redact_detect_pem,
    logger_redact_detect_url_userinfo,
    logger_redact_detect_api_key,
    logger_redact_detect_pan,
    logger_redact_detect_iban,
    logger_redact_detect_personnummer,
    logger_redact_detect_phone
]).
-define(OTP_SUMMARISE, [
    state, last_message, queue, postponed, messages, dictionary, log, timeouts, mfargs
]).

-type class() :: atom().
-type action() :: drop | hmac | keep.
-type config() :: #{
    deny_keys => [atom() | binary() | string()],
    deny_stems => [atom() | binary() | string()],
    key_classes => #{atom() | binary() | string() => class()},
    allow_keys => [atom() | binary() | string()],
    actions => #{class() => action()},
    detectors => [module() | {module(), map()}],
    otp_summarise => [atom()],
    hmac => #{key_provider => {module(), map()}, bytes => pos_integer()},
    match_limit => pos_integer(),
    max_depth => pos_integer(),
    max_elements => pos_integer(),
    max_scan_bytes => pos_integer()
}.
-type policy() :: #{
    keys := #{binary() => {class, class()} | allow},
    stems := binary:cp() | none,
    actions := #{class() => action()},
    detectors := [
        #{module := module(), state := term(), class := class(), keywords := binary:cp() | all}
    ],
    prefilter := binary:cp() | all | none,
    otp_summarise := #{atom() => true},
    hmac_bytes := 4..32,
    max_depth := pos_integer(),
    max_elements := pos_integer(),
    max_scan_bytes := pos_integer(),
    otp := boolean()
}.

-doc "The default configuration, as a map that can be adjusted and passed to `compile/1`.".
-spec defaults() -> config().
defaults() ->
    #{
        deny_keys => ?DENY_KEYS,
        deny_stems => ?DENY_STEMS,
        key_classes => ?KEY_CLASSES,
        allow_keys => [],
        actions => ?ACTIONS,
        detectors => ?DETECTORS,
        otp_summarise => ?OTP_SUMMARISE,
        hmac => #{bytes => 10},
        match_limit => 100000,
        max_depth => 12,
        max_elements => 2000,
        max_scan_bytes => 16384
    }.

-doc "Compiles a configuration. Raises on invalid input, so call it before installing.".
-spec compile(config()) -> policy().
compile(Config) when is_map(Config) ->
    #{
        deny_keys := DenyKeys,
        deny_stems := DenyStems,
        key_classes := KeyClasses,
        allow_keys := AllowKeys,
        actions := Actions,
        detectors := Detectors,
        otp_summarise := OtpSummarise,
        hmac := Hmac,
        match_limit := MatchLimit
    } = Merged = maps:merge(defaults(), Config),
    Keys = maps:merge(
        #{N => {class, Class} || K := Class <- KeyClasses, N <- [normalise_key(K)], is_binary(N)},
        #{N => {class, secret} || K <- DenyKeys, N <- [normalise_key(K)], is_binary(N)}
    ),
    Compiled = [detector(D, MatchLimit) || D <- Detectors],
    #{
        keys => maps:merge(
            Keys, #{N => allow || K <- AllowKeys, N <- [normalise_key(K)], is_binary(N)}
        ),
        stems => stems([N || S <- DenyStems, N <- [normalise_key(S)], is_binary(N)]),
        actions => maps:merge(?ACTIONS, Actions),
        detectors => Compiled,
        prefilter => prefilter(Compiled),
        otp_summarise => maps:from_keys(OtpSummarise, true),
        hmac_bytes => clamp(positive(maps:get(bytes, Hmac, 10))),
        max_depth => positive(maps:get(max_depth, Merged)),
        max_elements => positive(maps:get(max_elements, Merged)),
        max_scan_bytes => positive(maps:get(max_scan_bytes, Merged)),
        otp => false
    }.

-doc """
The active policy. If none is stored yet, for example because the filter was
configured in `sys.config` and runs before the application starts, the default
policy is compiled and stored.
""".
-spec current() -> policy().
current() ->
    case stored() of
        undefined ->
            Policy = compile(#{}),
            store(Policy),
            Policy;
        Policy ->
            Policy
    end.

-spec stored() -> dynamic().
stored() ->
    persistent_term:get(?PERSISTENT_KEY, undefined).

-spec store(policy()) -> ok.
store(Policy) ->
    persistent_term:put(?PERSISTENT_KEY, Policy).

-spec erase() -> ok.
erase() ->
    _ = persistent_term:erase(?PERSISTENT_KEY),
    ok.

-doc "Lowercases ASCII and drops `_` and `-`. Returns `undefined` for keys that are not text.".
-spec normalise_key(term()) -> binary() | undefined.
normalise_key(Key) when is_atom(Key) ->
    normalise_key(atom_to_binary(Key));
normalise_key(Key) when is_binary(Key) ->
    <<<<(fold(C))>> || <<C>> <= Key, C =/= $_, C =/= $->>;
normalise_key(Key) when is_list(Key) ->
    case io_lib:printable_unicode_list(Key) of
        true -> <<<<(fold(C))/utf8>> || C <- Key, is_integer(C), C =/= $_, C =/= $->>;
        false -> undefined
    end;
normalise_key(_Key) ->
    undefined.

fold(C) when C >= $A, C =< $Z -> C + 32;
fold(C) -> C.

stems([]) -> none;
stems(Stems) -> binary:compile_pattern(Stems).

detector({Module, Opts}, MatchLimit) when is_atom(Module), is_map(Opts) ->
    State = Module:init(maps:merge(#{match_limit => MatchLimit}, Opts)),
    #{
        module => Module,
        state => State,
        class => Module:class(State),
        keywords => keywords(Module:keywords(State))
    };
detector(Module, MatchLimit) when is_atom(Module) ->
    detector({Module, #{}}, MatchLimit).

keywords(Keywords) ->
    case [K || K <- Keywords, is_binary(K)] of
        [] -> all;
        Binaries -> binary:compile_pattern(Binaries)
    end.

prefilter([]) ->
    none;
prefilter(Detectors) ->
    case [K || #{keywords := K} <- Detectors, K =:= all] of
        [] -> keywords(lists:append([D:keywords(S) || #{module := D, state := S} <- Detectors]));
        _ -> all
    end.

clamp(N) when N < 4 -> 4;
clamp(N) when N > 32 -> 32;
clamp(N) -> N.

positive(N) when is_integer(N), N > 0 -> N.
