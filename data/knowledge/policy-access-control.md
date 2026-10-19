# Access Control Policy

## Restricted areas
A-Finance, A-ServerRoom and B-Lab are restricted areas. Access is granted per department: Finance may enter
A-Finance; IT may enter A-ServerRoom; Engineering and Facilities may enter B-Lab; Security may enter all areas.
Every entry to a restricted area must match the person's department permissions.

## Legacy access groups
The group "legacy-all-access" dates from the old badge system and is deprecated. It must be removed from all
accounts. Any restricted-area entry granted only because of a legacy group, and not by the department's
permissions, is a policy violation and must be investigated, even when the door system logged it as "granted".

## Multi-factor authentication
All accounts must use MFA. Accounts that can export personal data (including global face-ID profiles) without
MFA are a critical risk. A successful login without MFA from outside the corporate network (10.0.0.0/8) must be
treated as a possible account takeover.

## After-hours access
Night-shift security staff patrol all areas between 19:00 and 06:00; their badge activity is expected.
Other staff may work after hours in areas their department permits. After-hours entry to an area the person is
not permitted to enter is a violation.
