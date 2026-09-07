# Verification results

Verified in the build environment using Python 3.12.13 on Linux. Windows was not separately tested.

Command: `python -m unittest -v`

**13 tests passed.** Coverage: threshold, below threshold, failure-only records, separated failures, late success, inclusive boundaries, group isolation, reset on success, duplicate-success suppression, unsorted input, invalid input, HTML escaping, and bundled dataset results.

| Sample scenario | Expected | Observed |
|---|---|---|
| Alice: 3 failures in 2 minutes, success 1 minute later | One alert | AUTH-001 |
| Bob: 1 failure then success | No alert | No alert |
| Charlie: failures 10 minutes apart then success | No alert | No alert |

Ten input events produced one alert. These are synthetic test results, not production detection metrics. The report generator was exercised by the sample run and automated tests; browser visual inspection was not performed.
