## Redis Setup

### Require a password

Brute forcing is easy-ish with Redis, so this should be a really long password (60 chars, uppercase, lowercase, numbers)
```
CONFIG SET requirepass "[PASSWORD]"
```

## TODO

* Cron job crate with a central timer/runner. Register cron jobs with the runner and pass closure for the runner to execute. Cron runner only runs when `--cron` argument is specified
* Throttle connections to secure endpoints (by IP) and test
* Test Redis utils
* Test "secure" endpoints
* Fix Docker environment
* Use more string slices to avoid extra allocations when creating structs
* Get Redis and email delivery set up
* Logout endpoint: VALIDATE THE TOKEN FOR THE USER FIRST!!! Currently, anyone could add anything to the blacklist
* Time limit the following endpoints: signin, otp, change_password, create user (clear create user cache daily)
* OTP endpoint needs to use a unix epoch that is `OTP_LIFETIME_SECS / 2` in the future so the code doesn't expire immediately. The endpoint should check `OTP_LIFETIME_SECS / 2` into the future and then the current time. The Redis cache should last for `2 * OTP_LIFETIME_SECS` to account for that.
* Pass in Unix Epoch time to OTP and JWT functions, then write tests verifying expiration is enforced
* Create integer error codes in an enum (EXPIRED, INVALID, INCORRECT_FORMAT, etc.)
* Use Redis to count how many times a person has attempted an OTP in the past few minutes. Clear the Redis cache every few minutes (based on floor(Unix Epoch / time increment))
* In models, can lifetime reference be used for things like Uuid in New_ structs?
* Add email address to JWT, find endpoints (and tests!) that can use that email address rather than making a database fetch
* Verify SQL injection is not possible with any endpoint
* Documentation:
  * `CREATE DATABASE budgetapp OWNER budgetappdbuser ENCODING UTF8;`
  * `CREATE DATABASE budgetapp_test OWNER budgetappdbuser ENCODING UTF8;`
* Make more checks before creating data (e.g. in handler, check if user in classroom before calling db util to create it)
* Should students have a school ID associated with them?
* Create a method of encrypting data in the database
* Fill out this Readme with relevant instructions and notices
* Prevent DDOS attacks against password hasher by setting a hard limit on how many login or create user requests can be performed per second (add requests to a queue), or cache IPs and restrict more than 2 attempts per second. Or both.
  * Caching IPs is probably the best way to go. Otherwise, an attacker could deny logins and sign-ups by filling the queue
* Keep save all refresh tokens belonging to a user in the database so they can all be blacklisted at once