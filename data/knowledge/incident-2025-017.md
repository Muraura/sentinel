# Past incident INC-2025-017: Cloned badge and data theft

## What happened
An attacker guessed the password of a contractor account that had no MFA, logged in remotely at night, and at the
same time an accomplice used a cloned copy of the contractor's badge to enter the server room. The server-room
camera was unplugged two minutes later. Customer records were exported over the next ten minutes.

## How it was detected
A security analyst noticed the remote login and the badge entry for the same person within minutes. The camera
"offline" event was first dismissed as a flaky device, which delayed the response by a day.

## Lessons learned
Treat a camera going offline right after a restricted-area entry as suspicious, never as a routine device fault.
Remove legacy access groups. Enforce MFA on every account that can export data.
