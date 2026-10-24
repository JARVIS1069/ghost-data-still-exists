# Design decisions

1. **Hybrid, deterministic first.** Correctness-critical logic (identity, rules, ordering, status) is code so it
   is reproducible and explainable. An LLM is limited to ambiguous request intent (temperature 0, JSON output,
   retries, heuristic fallback). With no key there are zero calls.
2. **Rules are data.** `deletion_rules.csv` is parsed at runtime; changing a rule changes the plan, nothing is
   hardcoded per category beyond mapping treatments to the contract's operation names.
3. **Identity.** Match on current email, then historical emails from the audit log; link records by email, phone,
   hash (including derived sha256 of every known email) and user id. Never by name alone, because look-alike decoy
   users exist.
4. **Point-in-time evidence.** Only evidence captured on or before `audit_at` counts. If sources disagree the
   riskiest state wins (a copy in any replica is still a copy).
5. **Ordering.** Contract order is FINDING → REMEDIATION → VERIFICATION. Recreate paths are stopped before any
   destructive step so a sync/restore cannot re-create deleted data; backups are retained but restore-blocked.
6. **COMPLETE** requires every copy in its rule-required state, no active flow or restorable backup, and retained
   records still present.
7. **Masked records.** Some accounts appear only as a 404 with no identifier. They are attributed through the
   activity stream by time proximity to `reported_at`, used for accounts only because the same trick produced
   false positives for analytics and support.
8. **Evaluation.** Labelled samples score status, step and field accuracy, set precision/recall, LCS and Kendall
   tau, with a mismatch report and a config comparison table.
9. **Package name.** `code/` shadows the stdlib, so the real code lives in `code/ghost_audit/` and `cli.py` adds
   its own directory to `sys.path`.
