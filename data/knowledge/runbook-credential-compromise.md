# Runbook: Suspected Credential Compromise

## Indicators
Several failed logins followed by a success from the same external IP; a login without MFA from outside the
corporate network; a script user agent (python-requests, curl) instead of a browser; activity outside the
person's normal hours, locations or areas; bulk data access shortly after the login.

## Immediate steps
1. Contact the account owner by phone (not email) to confirm whether the activity was theirs.
2. Propose disabling the account and revoking the badge until confirmed. These actions need approval.
3. Propose blocking the source IP address.
4. Check what was accessed or exported after the login; if personal data was exported, follow the Data
   Protection Policy (breach notification).
5. Preserve evidence: keep the logs, access records and camera footage for the window.

## Physical and remote together
A remote login and a physical badge entry for the same person within minutes means either a cloned or stolen
badge, or an accomplice on site. Treat it as high severity and check camera coverage for the entry.
