-module(logger_redact_detect_api_key).
-moduledoc """
Provider API keys with a fixed prefix: AWS access key IDs, GitHub tokens,
Stripe secret keys and Slack tokens. Class `secret`.
""".
-behaviour(logger_redact_detector).

-export([init/1, keywords/1, scan/2, class/1]).

init(Opts) ->
    logger_redact_detector:compile(
        ~"\\b(?:(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}|[sr]k_(?:live|test)_[0-9A-Za-z]{16,}|xox[abposr]-[0-9A-Za-z-]{10,})",
        Opts
    ).

keywords(_State) ->
    [
        ~"AKIA",
        ~"ASIA",
        ~"ghp_",
        ~"gho_",
        ~"ghu_",
        ~"ghs_",
        ~"ghr_",
        ~"github_pat_",
        ~"k_live_",
        ~"k_test_",
        ~"xox"
    ].

scan(Text, State) -> logger_redact_detector:regex(Text, State).

class(_State) -> secret.
