# Configuration

The policy is a map, passed to `logger_redact:install/1` or set as the `policy`
key of the `logger_redact` application environment. Every key is optional.

| Key | Default | Meaning |
|---|---|---|
| `deny_keys` | `password`, `secret`, `token`, `api_key`, `authorization`, `cookie`, `session_id` and others | Keys whose values are always dropped as class `secret` |
| `deny_stems` | `passw`, `secret`, `token`, `apikey`, `privatekey`, `authoriz` | Substrings that mark a key as `secret` |
| `key_classes` | `email`, `phone`, `msisdn`, `ip`, `device_id`, `personnummer`, `card_number`, `iban` and others | Maps a key to a class |
| `allow_keys` | `[]` | Keys whose values are kept as they are, without scanning |
| `actions` | see below | Maps a class to `drop`, `hmac` or `keep` |
| `detectors` | all built-ins except IP | Detector modules, or `{Module, Opts}` |
| `otp_summarise` | `state`, `last_message`, `queue`, `postponed`, `messages`, `dictionary`, `log`, `timeouts`, `mfargs` | Fields summarised in events with domain `[otp]` |
| `hmac` | `#{bytes => 10}` | `key_provider => {Module, Opts}` and the pseudonym length in bytes (4 to 32) |
| `match_limit` | `100000` | Regex match limit; hitting it redacts the whole binary |
| `max_depth` | `12` | Nesting depth after which terms are replaced |
| `max_elements` | `2000` | Elements per list, map or tuple after which the rest is replaced |
| `max_scan_bytes` | `16384` | Bytes scanned per binary; the rest is replaced |

Keys are compared after lowercasing ASCII and removing `_` and `-`, so
`password`, `Password`, `"pass-word"` and `<<"PASS_WORD">>` are the same key.
Atom, binary and charlist keys are treated alike.

## Actions

| Class | Default | Source |
|---|---|---|
| `secret` | `drop` | deny keys, PEM, URL credentials, API keys |
| `credential` | `drop` | JWT, bearer and basic credentials |
| `national_id` | `drop` | personnummer key or detector |
| `pan` | `drop` | card key or detector |
| `iban` | `drop` | IBAN key or detector |
| `email` | `hmac` | email key or detector |
| `phone` | `hmac` | phone key or detector |
| `ip` | `hmac` | IP key, or the opt-in detector |
| `device_id` | `hmac` | device and push token keys |

`drop` gives `[REDACTED:Class]`. `hmac` gives `[Class:KeyId:Hex]`, or falls
back to `drop` when no key is loaded. `keep` leaves the value to the other
rules. Unknown classes are dropped.

## HMAC keys

Pseudonyms are HMAC-SHA256 over the class and the value, so the same value
gives different pseudonyms in different classes. Keys come from a
`logger_redact_key` provider and must be at least 32 bytes. Use a separate key
per environment and rotate it on the same cadence as log retention. A
pseudonym is still personal data for whoever holds the key.

## Custom detectors

Implement the `logger_redact_detector` behaviour and add the module to
`detectors`. `keywords/1` should return literal anchors so most text is never
scanned.

## Formatter wrapper

`logger_redact_formatter` redacts again before an inner formatter runs, and
returns a fixed line if that formatter fails. Use it on handlers that ship logs
off the node.

## Elixir

Not yet tested with Elixir's Logger. If anything prepends a primary filter
after install, the guard moves this filter back to the front within
`guard_interval` milliseconds.
