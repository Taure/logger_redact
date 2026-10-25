# logger_redact

logger_redact is a primary filter for OTP `logger` that removes PII and secrets from every event before any handler or formatter sees it.

## What is it?

It redacts the structured event once, in the logging process, and fails closed: if anything goes wrong it emits a fixed safe event instead of letting OTP pass the original through. It understands OTP's own crash reports, which carry process state, mailboxes, dictionaries and start arguments.

```erlang
?LOG_INFO(#{what => login, email => ~"anna@example.se", password => ~"hunter2"}).
%% what: login, email: [email:k1:9f2c1a04b7e3d6c58a10], password: [REDACTED:secret]

?LOG_ERROR("invite to ~s failed", [~"anna@example.se"]).
%% invite to [REDACTED:email] failed

?LOG_INFO(#{what => invite_sent, to => logger_redact:classify(email, Address)}).
```

## Quick start

1. Add the dependency:

```erlang
{deps, [{logger_redact, {git, "https://github.com/Taure/logger_redact.git", {tag, "v0.1.0"}}}]}.
```

2. Add `logger_redact` to your release. Starting it installs the filter and a guard that keeps it first.

3. To cover events logged before the application starts, also declare the filter in `sys.config`:

```erlang
{kernel, [{logger, [{filters, log, [{logger_redact, {fun logger_redact_filter:filter/2, []}}]}]}]},
{logger_redact, [
    {policy, #{hmac => #{key_provider => {logger_redact_key_env, #{env => "LOG_PSEUDONYM_KEY"}}}}}
]}
```

## Why logger_redact

- **Fail closed** → OTP removes a crashing filter and logs the raw event. This filter never crashes, and a guard re-places it if anything displaces it.
- **OTP crash reports** → `state`, `last_message`, `queue`, `postponed`, `messages`, `dictionary`, `mfargs` and stack-frame arguments are summarised, keeping the shape OTP's formatters expect.
- **Keys, then markers, then patterns** → key rules are exact and cheap; `classify/2` marks values under uninformative keys; detectors scan text behind a literal prefilter.
- **Built-in detectors** → email, JWT, bearer credentials, PEM private keys, URL credentials, provider API keys, card numbers (Luhn), IBAN (mod-97), personnummer (date and Luhn), international phone numbers, and opt-in IP addresses.
- **Keyed pseudonyms** → classes that need correlation become versioned HMAC pseudonyms. Without a key they are dropped, never hashed.
- **Bounded** → depth, element count and scanned bytes are capped, and anything over a cap is replaced.
- **Extensible** → detectors and key providers are behaviours.
- **No dependencies** → `kernel`, `stdlib` and `crypto` only.

## Limits

Redaction covers `logger`. It does not cover `sys:get_state/1`, remote shells, crash dumps or `io:format`. Positional record fields have no names at runtime, so key rules cannot see inside records; OTP state fields are summarised for that reason. Implement `format_status/1` with `logger_redact:format_status/2` in processes that hold sensitive state.

See the [configuration guide](guides/configuration.md) for every option and default.

## Licence

Apache-2.0
