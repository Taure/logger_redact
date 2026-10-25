-module(logger_redact_key).
-moduledoc ~"""
Behaviour for HMAC key providers, and the private store for the active key.

Classes whose action is `hmac` are replaced by a keyed pseudonym such as
`[email:k1:9f2c1a04b7e3d6c58a10]`. The key ID prefix shows which rotation
window a pseudonym belongs to. Without a loaded key, `hmac` falls back to
`drop`; values are never hashed without a key.

```erlang
-module(my_vault_key).
-behaviour(logger_redact_key).
-export([load/1]).

load(#{path := Path}) ->
    {ok, Key} = my_vault:read(Path),
    {ok, ~"2026-10", Key}.
```

Configure it as `#{hmac => #{key_provider => {my_vault_key, #{path => ...}}}}`.
Keys must be at least 32 bytes.
""".

-export([load/1, pseudonym/3, erase/0]).

-define(PERSISTENT_KEY, {logger_redact, hmac_key}).
-define(MIN_KEY_BYTES, 32).

-callback load(Opts :: map()) -> {ok, KeyId :: binary(), Key :: binary()} | {error, term()}.

-doc "Loads a key from a provider and makes it active.".
-spec load({module(), map()}) -> ok | {error, term()}.
load({Module, Opts}) when is_atom(Module), is_map(Opts) ->
    case Module:load(Opts) of
        {ok, KeyId, Key} when is_binary(KeyId), is_binary(Key), byte_size(Key) >= ?MIN_KEY_BYTES ->
            persistent_term:put(?PERSISTENT_KEY, {KeyId, fun() -> Key end});
        {ok, _KeyId, _Key} ->
            {error, invalid_key};
        {error, Reason} ->
            {error, Reason}
    end.

-doc false.
-spec pseudonym(atom(), iodata(), 1..32) -> {ok, binary()} | error.
pseudonym(Class, Value, Bytes) ->
    case persistent_term:get(?PERSISTENT_KEY, undefined) of
        undefined ->
            error;
        {KeyId, Secret} when is_binary(KeyId), is_function(Secret, 0) ->
            <<Short:Bytes/binary, _/binary>> =
                crypto:mac(hmac, sha256, secret(Secret), [atom_to_binary(Class), 0, Value]),
            {ok, <<KeyId/binary, ":", (binary:encode_hex(Short, lowercase))/binary>>}
    end.

secret(Secret) ->
    case Secret() of
        Key when is_binary(Key) -> Key
    end.

-doc "Removes the active key, so `hmac` falls back to `drop`.".
-spec erase() -> ok.
erase() ->
    _ = persistent_term:erase(?PERSISTENT_KEY),
    ok.
