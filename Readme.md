# TODO

* Go through integration tests and split out edgecases into their own tests
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