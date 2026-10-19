# Runbook: Database Connection Exhaustion

## Symptoms
API errors such as "QueuePool limit ... reached, connection timed out", Postgres "sorry, too many clients
already", slow requests, and HTTP 504 Gateway Timeout responses from the API.

## Common causes
A batch job (re-indexing, migrations, reports) opening many connections; a connection leak after a deployment;
a sudden traffic spike. Check which jobs were running when the connection count started to rise.

## Steps
1. Find when the connection count started rising and what started at that time.
2. If a batch job is the cause, pause it or let it finish; the API recovers when connections are released.
3. Confirm recovery: errors stop and the connection count falls.

## Prevention
Run batch jobs off-peak and give them their own connection limit. Alert when connections exceed 80% of the maximum.
