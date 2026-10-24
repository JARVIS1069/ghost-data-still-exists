# Evaluation report

Validation set: 32 labelled sample cases (`sample_output.csv`). No labels or ids are hardcoded in the agent.

## Configuration comparison

| Config | Status acc. | Seq. exact | LCS | Kendall tau | Step recall | Exposed P/R | Recreate P/R |
|---|---|---|---|---|---|---|---|
| rules-only | 93.8% | 71.9% | 0.896 | 1.000 | 92.7% | 1.00/0.94 | 1.00/1.00 |
| rules-no-activity-linking | 93.8% | 28.1% | 0.686 | 0.844 | 81.3% | 1.00/0.94 | 1.00/1.00 |

## Status metrics (rules-only)

| Class | Precision | Recall | F1 |
|---|---|---|---|
| COMPLETE | 0.83 | 1.00 | 0.91 |
| INCOMPLETE | 1.00 | 0.91 | 0.95 |
| NOT_APPLICABLE | 0.00 | 0.00 | 0.00 |

Confusion matrix (rows = gold, columns = predicted):

| gold \ pred | COMPLETE | INCOMPLETE | NOT_APPLICABLE |
|---|---|---|---|
| COMPLETE | 10 | 0 | 0 |
| INCOMPLETE | 2 | 20 | 0 |
| NOT_APPLICABLE | 0 | 0 | 0 |

## Field-level accuracy (position-aligned steps)

| Field | Accuracy |
|---|---|
| phase | 98.4% |
| system_id | 94.6% |
| resource_id | 93.5% |
| operation | 92.9% |
| state | 93.5% |
| evidence_id | 96.7% |

## Custom evaluation cases (intent classification)

| Text | Expected deletion | Got | Reason | Pass |
|---|---|---|---|---|
| Please delete my account and all personal data. | True | True | plain English deletion | yes |
| Solicito la eliminación permanente de mi cuenta. | True | True | Spanish deletion | yes |
| このアカウントの完全な削除を依頼します。 | True | True | Japanese deletion | yes |
| Can you correct my surname without removing any of my records? | False | False | correction, keep data | yes |
| I'd like to download my data. Please keep the account as it is. | False | False | export request | yes |
| Please change the email on my profile; I want to keep using the service. | False | False | update request | yes |

## Mismatches with evidence

- **case_04** gold=COMPLETE pred=COMPLETE; missing [('VERIFICATION', 'account_004', 'VERIFY_RECORD_ABSENT')]
- **case_07** gold=INCOMPLETE pred=COMPLETE; missing [('FINDING', 'support_001', 'REPORT_REMAINING_RECORD'), ('REMEDIATION', 'support_001', 'DELETE_RECORD'), ('VERIFICATION', 'support_001', 'VERIFY_RECORD_ABSENT')]
- **case_10** gold=INCOMPLETE pred=INCOMPLETE; missing [('FINDING', 'support_002', 'REPORT_REMAINING_RECORD'), ('REMEDIATION', 'support_002', 'DELETE_RECORD'), ('VERIFICATION', 'support_002', 'VERIFY_RECORD_ABSENT')]; extra [('FINDING', 'support_002', 'REPORT_EXPOSED_PII'), ('REMEDIATION', 'support_002', 'REDACT_RECORD'), ('VERIFICATION', 'support_002', 'VERIFY_RECORD_REDACTED')]
- **case_12** gold=INCOMPLETE pred=COMPLETE; missing [('FINDING', 'analytics_9914', 'REPORT_REMAINING_RECORD'), ('REMEDIATION', 'analytics_9914', 'DELETE_RECORD'), ('VERIFICATION', 'analytics_9914', 'VERIFY_RECORD_ABSENT')]
- **case_17** gold=INCOMPLETE pred=INCOMPLETE; extra [('VERIFICATION', 'account_6523', 'VERIFY_RECORD_ABSENT'), ('VERIFICATION', 'tombstone_17', 'VERIFY_RECORD_REDACTED')]
- **case_18** gold=INCOMPLETE pred=INCOMPLETE; missing [('VERIFICATION', 'audit_record_6645', 'VERIFY_RECORD_PRESENT')]
- **case_20** gold=INCOMPLETE pred=INCOMPLETE; missing [('VERIFICATION', 'audit_record_5569', 'VERIFY_RECORD_PRESENT')]
- **case_22** gold=INCOMPLETE pred=INCOMPLETE; missing [('VERIFICATION', 'account_4990', 'VERIFY_RECORD_ABSENT')]; extra [('VERIFICATION', 'account_6829', 'VERIFY_RECORD_ABSENT')]
- **case_23** gold=INCOMPLETE pred=INCOMPLETE; missing [('VERIFICATION', 'account_410', 'VERIFY_RECORD_ABSENT')]; extra [('VERIFICATION', 'account_294', 'VERIFY_RECORD_ABSENT')]

## Failures found and improvements made

- Plain keyword matching mis-classified keep-the-account requests; added explicit keep/other cues and multilingual deletion stems.
- Evidence-less masked account deletions: added activity-stream linking, which raised account coverage on the samples (see the no-activity-linking row).
- Replica drift (record only in a failover replica) is detected by taking the riskiest state per instant across channels.
- Remaining misses are masked analytics/support rows that no identifier links to a person; these need extra metadata or an LLM/VLM and are listed above.
