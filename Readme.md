## Redis Setup


### Require a password

Brute forcing is easy-ish with Redis, so this should be a really long password (60 chars, uppercase, lowercase, numbers)
```
CONFIG SET requirepass "[PASSWORD]"
```
## Run all tests

```
cargo test -- --include-ignored --test-threads=1
```

## TODO MVP

* Get email delivery set up
  * OTP
  * Forgot Password
* Forgot password endpoint
* Fill out this Readme with relevant instructions and notices
* Documentation:
  * `CREATE DATABASE budgetapp OWNER budgetappdbuser ENCODING UTF8;`
  * `CREATE DATABASE budgetapp_test OWNER budgetappdbuser ENCODING UTF8;`
* Verify SQL injection is not possible with any endpoint

## TODO Later

* Create integer error codes in an enum (EXPIRED, INVALID, INCORRECT_FORMAT, etc.)
* Fix Docker environment
* Pool Redis connections
* Clean up `main()`
* Use more string slices to avoid extra allocations when creating structs
* Create a method of encrypting data in the database
* Save all refresh tokens belonging to a user (save them when they get issued) in the database so they can all be blacklisted at once
