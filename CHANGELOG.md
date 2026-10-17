# Changelog

## Unreleased (0.2.0rc1 candidate; not published)

- Reject exponent-overflow JSON numbers such as `1e999` and `-1e999` with `EvidenceError`, matching the documented finite-number rule.
- New optional byte budgets: `max_file_bytes` / `max_total_bytes` (library, keyword-only) and `--max-file-bytes` / `--max-total-bytes` (CLI, `create` and `verify`). Oversized files are refused before reading, growth past a limit is detected with at most one extra byte read, and the total budget counts every byte read in one call. Exceeding a budget is the new `resource_limit` issue (exit 1). Defaults are unchanged: no limit.
- Human output now also says matching hashes do not prove authenticity or authorization.
- Restore the documented pull-request Python/platform matrix; README distinguishes configured jobs from executed verification.
- PyPI metadata (keywords, classifiers, homepage and changelog URLs), README pitch, badge placeholders and install-from-PyPI note.

## 0.1.0

Initial release of delivery-evidence-check: dependency-free Python CLI and library, strict JSON
validation, synthetic examples, human and JSON reports, and behavior tests.
