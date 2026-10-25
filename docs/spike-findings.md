# Spike findings (2026-10-24, OTP 29.1.2)

Run with `rebar3 ct` (leak and fail-open suites) and `rebar3 as bench ct --dir bench`.

## Claims verified against stock OTP

| Claim | Result | Test |
|---|---|---|
| A crashing primary filter is removed permanently | Confirmed | `failopen_SUITE:stock_crashing_filter_*` |
| The event that crashed it reaches handlers unredacted | Confirmed (`handle_filter_failed` returns `ignore`) | same |
| A bad return value is treated the same way | Confirmed | `failopen_SUITE:stock_bad_return_*` |
| A debug report re-emits the raw event (`{log_event, Log}`) | Confirmed at primary level `debug` | same |
| `add_primary_filter/2` prepends | Confirmed | `failopen_SUITE:add_primary_filter_prepends` |
| gen_server state and last message leak in crash reports | Confirmed | `leak_SUITE:baseline.gen_server_state` |
| `function_clause` stack frames leak call arguments | Confirmed | `baseline.gen_server_function_clause`, `baseline.function_clause_args` |
| A crashing `format_status/1` in gen_server hides state but not last message | Confirmed | `baseline.gen_server_format_status_crash` |
| A crashing `format_status/1` in gen_statem leaks raw data | **Confirmed, OTP bug**: `gen_statem:error_info/7` ignores the `'EXIT'` key that `gen:format_status/4` sets | `baseline.gen_statem_format_status_crash` |
| proc_lib crash reports leak dictionary and mailbox | Confirmed | `baseline.proc_lib_crash` |
| Supervisor reports leak child start args | Confirmed | `baseline.supervisor_start_args` |

All twelve leak cases pass with the filter installed: no canary in the event term or the formatted output, and no report_cb crash.

## Design consequences

- Summaries must keep the outer shape. `gen_statem:format_log` comprehends over `log` and matches `{N, _}` on `timeouts`, so lists become `[Marker]` and tuples keep atoms (`{idle, <<"[REDACTED map size=2]">>}`).
- `mfargs` belongs in the OTP summary keys; it is not a stack frame shape.
- `re:run/3` returns `nomatch` when `match_limit` is hit unless `report_errors` is passed. Without it the limit fails open.
- `string:lowercase/1` on keys was the main cost and a crash path on invalid UTF-8. ASCII folding fixed both.

## Cost per event (µs, filter vs `logger_formatter:format/2`)

| Scenario | Filter | Format |
|---|---|---|
| Clean 4-key report | 1.4 | 10.7 |
| Report with `password` key | 0.9 | 8.9 |
| Format string with email arg | 1.3 | 5.8 |
| 200-byte string, no `@` | 0.3 | 7.0 |
| String with email | 1.6 | 5.1 |
| gen_server crash, 1000-entry state | 2.5 | 2219 |
| Report with 500 nested player maps and emails | 1101 | 923 |

Typical events cost a fraction of formatting. Large nested reports cost about as much as formatting them; candidates are an atom-key verdict cache and a cheaper email scan.

## Not yet covered

OTP 28 run, Elixir translator ordering, remote group-leader events, a supervised watchdog, detectors beyond email, HMAC pseudonyms, the formatter wrapper.
