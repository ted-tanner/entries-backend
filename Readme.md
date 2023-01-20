# The Budget App (Server)

## Cloning Repository

This repository has a submodule dependency, so a simple `git clone` won't work. The repository must be cloned recursively:

```
git clone --recursive git@github.com:ted-tanner/the-budget-app-server-rust.git
```

## Contents

- [Dependencies](#dependencies)
- [Dev Dependencies](#dev-dependencies)
- [Setup](#setup)
  - [PostgreSQL Setup](#postgresql-setup)
  - [Diesel Migrations](#diesel-migrations)
  - [Redis Setup](#redis-setup)
- [Server Configuration](#server-configuration)
  - [Connections](#connections)
  - [Hashing](#hashing)
  - [Keys](#keys)
  - [Lifetimes](#lifetimes)
  - [Security](#security)
  - [Workers](#workers)
- [Running the Server](#running-the-server)
  - [Files Needed by the Server](#files-needed-by-the-server)
  - [Command-line Arguments](#command-line-arguments)
- [Testing the Server](#testing-the-server)
  - [Unit and Integration Tests](#unit-and-integration-tests)
  - [Manual Testing](#manual-testing)
- [Building the Server](#building-the-server)
- [Checking your Code](#checking-your-code)
- [To Do](#to-do)
  - [Minimum Viable Product](#minimum-viable-product)
  - [Do It Later](#do-it-later)

## Dependencies

1. PostgreSQL (14.1)

    [Download PostgreSQL here](https://www.postgresql.org/download/)

    For macOS, don't install PostgreSQL via Homebrew. There are some issues with the Homebrew installation (since version 12) that can cause Postgres to stop working. On Linux, you may also need to install the libpq-dev package from `apt`.

2. Redis (6.2.6)

    [Download Redis here](https://redis.io/download)

## Dev Dependencies

1. Rust Toolchain (Latest stable, edition 2021)

    [Installation instructions can be found here](https://www.rust-lang.org/tools/install)

2. *Optional:* Docker and `docker-compose`

    No promises that the Docker configuration will be up-to-date. Docker is used only when setting up an environment on a non-dev, non-production machine.

    If the Docker configuration is up to date, one should only need to run `docker-compose up` to run the full environment including Redis and Postgres.

    [Download Docker here](https://www.docker.com/products/docker-desktop)

## Setup

### PostgreSQL Setup

Start the PostgreSQL service if not already running.

```
psql
```

Depending on the Postgres version you install, the setup script may fail to create a database for your user. If you get this error:

    psql: error: FATAL:  database "tanner" does not exist

you'll need to run the following:

```
createdb
```

If the `createdb` command fails, do the following:

1. Log into the `postgres` user account in the CLI.

    ```
    sudo su - postgres
    ```

2. Connect to the database server using the `postgres` role.

    ```
    psql -U postgres
    ```

3. Now, create a role for your machine user account.

    ```
    CREATE ROLE [username] WITH createdb LOGIN PASSWORD '[password]';
    ALTER USER [username] WITH createrole;
    ```

4. Verify the new role has been created in the PostgreSQL CLI.

    ```
    \du
    ```

5. Return to your user by `exit`ing twice. Then run `createdb`

    ```
    exit
    exit
    createdb
    ```

Now, in `psql`, create a user and a database for the application.

```
CREATE USER budgetappdbuser WITH ENCRYPTED password '[password]';
ALTER USER budgetappdbuser CREATEDB;
CREATE DATABASE budgetapp OWNER budgetappdbuser ENCODING UTF8;
```

Obviously, for production the password should be something that doesn't suck and won't be lost. By "doesn't suck" I mean that this password is *extremely* sensitive and should be random and long (like, 40+ characters long).

### Diesel Migrations

**WARNING:*** Be extremely cautious when running migrations. Migrations may cause data loss. Migrations that get run in a production environment must be thoroughly tested in a staging environment and one must be careful not to accidently type the wrong command (or the right command more than once).

The server uses an ORM library called Diesel. Diesel wraps up the migrations nicely within the binary so one can write the SQL for the migrations then not have to deal with a bunch of SQL files when actually running the migrations--they instead get compiled into the binary.

To run the migrations, just run the (properly configured) server with the `--run-migrations` flag:

```
./budgetapp-server --run-migrations
```

During development, it might be helpful to be able to quickly run, revert, and redo the migrations on a test database. Diesel provides a tool for doing this, which can be installed via Cargo:

```
cargo install diesel_cli --no-default-features --features postgres
```

With the Diesel CLI installed, you can run the following commands (assuming your current working directory is the project folder with the migrations):

```
# Runs the migrations
diesel migration run

# Reverts the latest migration
diesel migration revert

# Restarts with a clean slate. Undoes all migrations and then runs them again.
diesel migration redo
```

### Redis Setup

Redis should pretty much work of the box, but you might like to add a password (especially in a production environment). Redis passwords are hashed quickly and therefore easily brute forced, so the password in production needs to be long and random.

With the Redis server running (run `redis-server`), open the Redis CLI (run `redis-cli`) and enter the following:

```
CONFIG SET requirepass "[password]"
```

## Server Configuration

Certain behaviors of the server can be configured with the `budgetapp.toml` file in the conf folder. This configuration file (and the folder containing it) must be included alongside the binary distribution of the server in order for the server to run properly.

**SECURITY WARNING:** In production, the `budgetapp.toml` file contains sensitive secrets. DO NOT push any sensitive keys to a git repository or make the file viewable or accessible to an untrusted party (or even to a trusted party if it can be avoided).

The configuration settings from `budgetapp.toml` are documented below:

### Connections

* `database_uri`

  The URI used to connect to Postgres, including the database name, username, and password.

* `max_connection_pool_size`

  The maximum size of the thread pool of database connections. This value must be at least as high as the configured number of `actix_workers` to prevent resource starvation.

### Hashing

The server uses the Argon2 hashing algorithm for passwords. Argon2 is a memory-hard algorithm, meaning that the machine running the hash function must use a specified amount of RAM or the computation becomes untennable. It is important for security that the RAM requirement be high enough to make brute-forcing a password infeasible for an attacker who has obtained the hashes. The `hash_mem_size_kib` parameter should be as high as can be afforded, then other parameters (such as iterations and lanes) can be adjusted to ensure the hashing is computationally expensive. Ideally, hashing a password should take 0.5s to 1.5s on modern hardware.

* `hash_iterations`

  The number of times the password is rehashed. Increasing this number makes hashing take longer, thereby increasing security.

* `hash_length` (Sufficient entropy is sufficient, shouldn't take up a lot of space)

  The length (in characters) of the output of the hash. The important thing here is to ensure that the entropy of the hash is higher than that of a strong password. After a certain point, a longer hash doesn't really increase security and just takes more space in the database.

* `hash_mem_size_kib`

  The amount of RAM (in kibibytes) a system needs to be able to calculate a hash without the computation becoming infeasibly expensive. This is probably the most import parameter for the Argon2 hash. The more RAM required for hashing, the more secure the passwords are. Make this as high as can be afforded.

  The `hash_mem_size_kib` must be a power of 2 (e.g. 262144, 524288, or 1048576).

* `hash_lanes`

  The number of threads required to feasibly calculate the hash. An attacker with specialized hardware will likely not be constrained by threads in the same way he/she will be constrained by memory (GPUs tend to have more memory channels than CPUs). The hardware the server is running on will likely be more constrained than an attacker's hardware so, if the memory parameter is adequate, the number of lanes is not too important.

* `salt_length_bytes`

  The length of the randomly-generated salt that gets hashed with the password. It is recommended to be at least 128-bits (16 bytes) long.

### Keys

These keys are secret and should be handled with care. They should be randomly generated in a cryptographically-secure way.

* `hashing_key`

  Key used for password hashing.

* `otp_key`

  Key used for signing Time-based One-Time Passcodes (TOTP).

* `token_signing_key`

  Key used for signing auth tokens.

### Lifetimes

These configurations describe how long tokens last before being considered invalid.

* `access_token_lifetime_mins`

  The amount of time for which access tokens will be valid, in minutes.  The access token gets sent by the client with every request that needs to be authenticated. Because of the repeated usage of this token, it should be invalided quickly to prevent attackers who obtain the token from retaining sustained access.

* `otp_lifetime_mins`

  The amount of time for which TOTP codes will be valid. Also half the maximum amount of time for which siginin tokens will be valid.

  The server issues passcodes that are valid `otp_lifetime_mins` in the future to prevent user access from expiring imediately after a code is issued when the time interval lapses. The server will accept a current code or a code slightly in the future such that a user who is issued a code just before the completion of a time interval will have a working code for `otp_lifetime_mins` whereas a user who is issued a code just *after* the completion of a time interval will have a working code for `2 * otp_lifetime_mins`.

  Failed passcode attempts by a user are recorded and limited to prevent brute-forcing the code (see the `otp_max_attempts` configuration).

* `refresh_token_lifetime_days`

  The amount of time for which refresh tokens will be valid, in days. A refresh token is used to obtain a new access token when the access token is lost or expired. Refresh tokens are blacklisted once used and a new refresh token is issued. Once the user device's refresh token expires, the device is effectively logged out. The consequence is that if a user's device doesn't make an authenticated request for `refresh_token_lifetime_days`, the device will be logged out. However, a device that consistently makes an authenticated request at least once every `refresh_token_lifetime_days` can remain logged in indefinitely.

  When determining the lifetime of refresh tokens, consideration should be made in regard to user convenience. Too short of a lifetime will result in a poor user experience because the user may have to sign in frequently.

### Security

Miscellaneous configuration(s) related to server or data security.

* `otp_max_attempts`

  The maximum number of allowed failed TOTP attempts within `2 * otp_lifetime_mins`. The number of attempts is cached, but the cache is reset every `2 * otp_lifetime_mins`. The throttling of number of attempts is done because of the ease at which an 8-digit numerical code can be brute-forced and in compliance with [RFC4226 section 7.3](https://datatracker.ietf.org/doc/html/rfc4226#section-7.3).

### Workers

* `actix_workers`

  Number of worker threads in the server's thread pool that will be made available to handle incoming requests. Because of the Actix actor model used by the handlers, each worker thread may be able to handle multiple requests simultaneously while resources (such as database fetches) are awaited upon.

## Running the Server

To run the server via Cargo, the following commands can be used:

```
# Debug mode
cargo run

# Release mode
cargo run --release

# Production mode
cargo run --profile production
```

The compiled server binary can be run from the command-line. See the [Command-line Argments](#command-line-arguments) section below for a list of available arguments that can be passed to the executable.

### Files Needed by the Server

The server expects a few files to be present in the working directory from which it is run. The `assets` and `conf` directories (and their contents) are required for the server to start up correctly.

### Command-line Arguments

The server accepts a number of command-line arguments to change default behavior. Available arguments are listed below:

* `--port [NUMBER]`

  Specifies the port to run the HTTP server on. Defaults to `9000`.

  ##### Example
  ```
  ./budgetapp-server --port 9002
  ```

* `--ip [IP_ADDR]`

  Specifies the IP address the HTTP server will be served from. Defaults to `127.0.0.1`.

  ##### Example
  ```
  ./budgetapp-server --ip 10.0.0.12
  ```

* `--run-migrations`

  If specified, the server will attempt to run any database migrations that have been encoded into its binary on startup.

  ##### Example
  ```
  ./budgetapp-server --run-migrations
  ```

* `--schedule-cron-jobs`

  If specified, the server will schedule maintenence tasks to be run periodically. In a given environment, only one instance of the server should be run with this argument to avoid repeats or collisions of scheduled jobs (which can result in a poor user experience and/or security vulnerabilites). 

  ##### Example
  ```
  ./budgetapp-server --schedule-cron-jobs
  ```

Multiple command-line arguments can be specified and in any order. For example:

```
./budgetapp-server --schedule-cron-jobs --port 8765 --run-migrations
```

When running the server with `cargo run`, command-line arguments specified after `--` will be passed through to the server:

```
cargo run --release -- --port 9001 --schedule-cron-jobs
```

## Testing the Server

### Unit and Integration Tests

Unit and integration tests are run by `cargo`. They do interact with Redis and Postgres, so **make sure the server is configured for a testing environment before running the tests** (see [Server Configuration](#server-configuration)).

The vast majority of tests can be run asychronously across multiple threads without interfering with one another. To run the tests, make sure the environment is properly configured and running (including Redis and Postgres) and run the following command:

```
cargo test
```

Because the tests interact with Postgres and Redis, running them asynchronously may cause some tests to fail if multiple tests simultaneously alter state. By default, when you run `cargo test`, the tests that can cause problems will be filtered out. You can run *all* of the tests synchronously on a single CPU with the following command:

```
cargo test -- --include-ignored --test-threads=1
```

### Manual Testing

You can hit the endpoints using cURL. Here is an example of how to make a POST request with cURL:

```
curl -X POST "http://localhost:9000/api/auth/login" -d "email=test@example.com&password=aT3stPa$$w0rd"
```
or
```
curl -X POST "http://localhost:9000/api/auth/login" -H "Content-Type: application/json" -d '{"email": "test@example.com", "password": "aT3stPa$$w0rd"}'
```

To authenticate, send an access token in the `Authorization` header:

```
curl -X GET "http://localhost:9000/api/user/get" -H "Authorization: Bearer [ACCESS_TOKEN]"
```

To refresh an access token, you need to use a refresh token (you should get it upon login):

```
curl -X POST "http://localhost:9000/api/auth/refresh_token" -H "Content-Type: application/json" -d '{"refresh_token": "[REFRESH_TOKEN]"}'
```

## Building the Server

To make a debug build, run:

```
cargo build
```

To make a release build with -O3 optimizations, run:

```
cargo build --release
```

## Checking your Code

Rust takes a freakishly long time to compile. Here's my recommendation: don't. Instead of using `cargo run` or `cargo build`, use the following:

```
cargo check
```

`cargo check` runs the lexical analyzer, the parser, and the borrow-checker, which can still take a significant amount of time.

To improve code quality and find stupid mistakes that add extra CPU cycles to an operation that could be done more quickly, Cargo includes an excellent linter called Clippy (no relation to Windows Clippy). To run in, use the following:

```
cargo clippy
```

I can't mention the linter without mentioning the auto formatter:

```
cargo fmt
```

## To Do

This list is not comprehensive; it's mostly just a "don't forget to do this" list. There might also be TODO comments throughout the code that can be found by running something like this:

```
find . -name "*.rs" | xargs grep -n "TODO"
```

### Client

* Currency may be specified on each budget
* Make invites/requests separate from regular notifications (like a separate section of the notifications view on the client). Then, pull notifications but also pull invites.
* Premium user status is only verified client-side
* Premium usership should have teirs: perhaps $2.99/month unlocks the number of budget entries while $3.99/month unlocks number of entires *and* budget sharing
* Verify user age
* Warn a user that they cannot unshare a budget once it is shared

#### IMPORTANT Data Syncronization Stuff
* All data should have a `syncedTimestamp` or `synced_timestamp`. Data older than X minutes will get pulled from the server. The timestamp should be based on the server's time (on app startup, calculate a delta between the server time and the client's time (in UTC). Count the minutes the clock is off and use that delta to calculate the synced_timestamp. UPDATE THE DELTA UPON TOKEN REFRESH.
  - THIS DELTA SHOULD BE USED FOR CHECKING TOKEN EXPIRATIONS AS WELL.
* If the last synchronization with the server was more than one year ago (according to the server's time), all data needs to be deleted and pulled again. The server's `tombstone` table will be cleared of tombstones older than a year.

### Tests

* Tombstone DAO in its entirety
* All methods for `budgetapp_job_scheduler::jobs::delete_users::DeleteUsersJob`
* `budgetapp_utils::db::user::initiate_user_deletion`
* `budgetapp_utils::db::user::cancel_user_deletion`
* `budgetapp_utils::db::user::delete_user`
* `budgetapp_utils::db::user::get_all_users_ready_for_deletion`
* `budgetapp_utils::db::user::get_user_tombstone`
* Test creating an entry and associating it with a budget
* `budgetapp_utils::db::user::set_last_token_refresh_now`
* Test set_last_token_refresh_now works in `budgetapp_server::handlers::auth::verify_otp_for_signin` and `budgetapp_server::handlers::auth::refresh_tokens`
* Test all token error cases in `budgetapp_server::handlers::auth`. Test sending blacklisted token, expired token, etc. and make sure the proper HTTP status is returned and user does not get authenticated
* Test the `server_time` returned by all handlers in `budgetapp_server::handlers::auth` that return a token pair.

### End-to-end Encryption Scheme
* When a new user is created, an encryption key is randomly generated for the user *on the client*. This encryption key gets encrypted twice, once with a PBKDF2 hash of the user's password (the server stores the salt for the hash) and once with the a recovery key that is hashed in the same way. Both encryptions are stored on the server and sent to the client. The client can decrypt the user's encryption key (using their password) and store it securely (KeyChain, for example, guarded with FaceID).
* Recovery key is a 32-character alphanumeric string. It gets hashed with PBKDF2 using a salt that is stored on the server. That hash is the key to decrypt the user's encryption key.
* Authentication string for sign in is a separate PBKDF2 hash of the user's password with a different salt. This hash gets re-hashed (Argon2) before being stored in the database
* Encrypt user preferences using a user's key
* All user data (budgets, entries, user preferences, etc.) should be stored as an ID, associated_id (optional, e.g. a budget_id for an entry), a modified_timestamp, and an encrypted blob
  - Tombstones should still exist
* Each budget (along with its associated entries) has its own encryption key. These keys are encrypted with the user's own key and then synchronized with the server
* Encrypt user's private key using the user's password. Public key will be shared publicly along with user info
  - Clients should rotate keys every once-in-a-while
* When sending a budget share request, the budget's encryption key is encrypted with the recipient's public key. If the recipient accepts the invite, the server sends over the encrypted key (or just deletes the invitation and encrypted key if recipient declines). Both users save the encryption key (encrypting it with their own keys and synchronizing the encrypted keys with the server). The key gets saved in in the `user_budgets` table for the user.
* When a user leaves a budget share, they simply delete the key.
* To synchronize data, the server should send a list of existing IDs of a type (e.g. the IDs of all budgets a user belongs to) along with the `modified_timestamp`. The client can request data as needed. Tombstones should exist so user can check if data has been deleted.
* Things that aren't encrypted:
  - User's email address
  - A list of users one shares budgets with
  - A user's list of buddies
  - A count of how many budgets a user has
  - A count of how many entries are in a budget
  - Timestamps of when data was last modified
  - Timestamp of user's last login

### Minimum Viable Product

* Remove `origin_table` field from tombstones
* End-to-end encryption
* Delete buddy request once accepted or declined
* Try wrapping `web::Data` fields in a mutex or a `RefCell` so it can be zeroized
* Create a single `web::block` per handler (where possible). DB calls may be synchronous inside the block.
* Create multi-column indices for tables that are always looked up by more than a single column (e.g. a budget is searched by `user_id` and `budget_id` together, and `tombstone` table uses `user_id` and `item_id`). This can be done by simply making a multicolumn primary key (see https://docs.diesel.rs/master/diesel/associations/derive.Identifiable.html for Diesel implementation). Be sure to replace `.filter()`s with `.find()`s.
* Get rid of `is_deleted`. Delete everything immediately, but put the ID in a `tombstones` table.
  - Tombstones need to be associated with a user_id for security and for deletion purposes.
  - The server should check tombstones automatically if an item isn't found but is in the tombstone table and respond that the item has been deleted with an HTTP "410 Gone" (do this for the `user_tombstone` too). Make sure this only works with the proper authorization and user_id from a token.
  - `item_id` in `tombstone` table is the primary key and the ID of the deleted item
  - Tombstones should be cleared after 366 days
* Password reset flow
* Send the server's time in the heartbeat?
* Endpoint for checking if user is listed for deletion
* Create user endpoint must have an `acknowledge_agreement` field. If the field is false, the endpoint returns a 400 error
* White paper, security audit

*By 9/16*

* Endpoints for editing, adding, and deleting categories for a budget. Perhaps this should be done with a single endpiont that edits the categories for a given budget and accepts a list of all the categories and does the necessary replacements (the edit/add/delete can be separate functions in DB utils, but they should be able to handle multiple at a time to avoid the N+1 queries problem)?
  
*By 9/30*

* Edit handler for entries
* Create delete handlers (and db::utils) for entry

*By 10/14*

* Create edit handlers (and db::utils) for user and entry

*By 10/28* 
 
* Get email delivery set up
  * OTP
  * Forgot Password
* Forgot password endpoint
 
*By 12/9*

* Email notifications for the following:
  - User deletion initiated
  - Budget shared? Users need a way to turn off this notification

### Do it later

* Only get certain fields of a user or budget when requesting. i.e. use `SELECT field1, field2, etc WHERE ...` in query instead of `SELECT * WHERE ...`
* Handle all checks if user is in budget within the query being made
* Use more string slices to avoid extra allocations when creating structs. Use lifetimes to accomplish this
* Replace all Diesel `sql_query`s with Diesel's DSL syntax
* Budget comments, entry comments
  - Reactions to said comments
* As an optimization, Daos shouldn't use `Rc<RefCell<DbConnection>>`. They should just pass `mut` pointers (which is safe because the Dao will only ever access one at a time).
* Validation for `budgetapp_utils::password_hasher::HashParams` (e.g. make sure `hash_mem_size_kib` is at least 128 and is a power of 2)
* Use lifetimes to reduce they copying of strings (e.g. TokenPair, TokenClaims, perhaps some of the OutputX structs, etc)
* Budget user get request logic should be handled in a query to eliminate multiple queries
* Create mock in Dao to test DB stuff in budgetapp-utils
* Replace lazy_static with OnceCell
* Save all refresh tokens belonging to a user (save them when they get issued) in the database so they can all be blacklisted at once.
* In `budgetapp_server::handlers::budget::remove_budget(...)`, make deleting the budget non-blocking. Users have already been removed from the budget, so the handler can return without finishing deleting the budget. See the comment in the code for an idea of how to do this performantly
* OTP attempts, password attempts, and blacklisted tokens can be moved to Redis
* Comments (budget comments, entry comments, etc.)
* Publicly export models (so imports look like this `use crate::models::BuddyRequest;` rather than `use crate::models::buddy_request::BuddyRequest;`
* To ensure user is in budget, don't make db query. Just filter db items using a join with the UserBudgetAssociation
* Reject accept/decline budget shares and buddy requests if already accepted or declined
* Admin console
* If user deletion fails, put a record in another table for manual deletion later. When implementing this, make sure in `budgetapp_utils::db::user::delete_user` the request gets deleted from the requests table before attempting to delete user data so the request doesn't get run again in subsequent runs of the delete_users job.
* Give the job scheduler a thread pool and queue up jobs for the pool to execute so multiple jobs can run at once

### Note on timezones

* Budget and entry dates are fixed. The timezone the user in is not relevant; the budgets will always end according to the date for the user.
