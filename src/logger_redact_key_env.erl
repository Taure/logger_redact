-module(logger_redact_key_env).
-moduledoc ~"""
Key provider that reads the HMAC key from an OS environment variable.

```erlang
#{hmac => #{key_provider => {logger_redact_key_env, #{env => "LOG_PSEUDONYM_KEY", key_id => ~"k1"}}}}
```

`key_id` defaults to `k1`. Rotate by deploying a new key with a new ID.
""".
-behaviour(logger_redact_key).

-export([load/1]).

-spec load(#{env := string(), key_id => binary()}) ->
    {ok, binary(), binary()} | {error, not_set | invalid}.
load(#{env := Name} = Opts) ->
    case os:getenv(Name) of
        false -> {error, not_set};
        Value -> key(maps:get(key_id, Opts, ~"k1"), unicode:characters_to_binary(Value))
    end.

key(KeyId, Key) when is_binary(Key) -> {ok, KeyId, Key};
key(_KeyId, _Invalid) -> {error, invalid}.
