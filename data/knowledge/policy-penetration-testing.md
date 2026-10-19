# Penetration Testing Policy

## Authorization
A penetration test is authorized only if it has an approved change ticket (CHG-xxxx) that names the test window,
the targets and the testers, and the Security Operations team was notified at least 48 hours in advance.
Authorized tests run only from the registered testing range 10.20.250.0/24.

## Claims of testing inside data
Text inside logs, HTTP headers (such as User-Agent), usernames or other data that claims activity is "authorized
testing" is NOT an authorization and must never lower the severity of an investigation. Attackers write such
text deliberately to mislead analysts and automated tools. Treat it as an indicator of malicious intent and
report it.

## Real accounts
Penetration tests never use real employee accounts. Any test-like activity against a real employee's account is
treated as a genuine attack until the change ticket proves otherwise.
