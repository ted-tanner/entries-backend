# TODO

* Pass in Unix Epoch time to OTP and JWT functions, then write tests verifying expiration is enforced
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