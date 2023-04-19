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

* Follow password guidelines from NIST (perhaps require more characters given that user data is encrypted using the given password)
* The client needs to make sure the UNIX timestamp it receives from the server when refreshing token is within a minute of the client's UNIX timestamp
* Currency should be specified on each budget, default currency in user_preferences
* The client needs to be prepared for a category to be deleted. Entries will still have a reference to the deleted categories, so check for the category tombstone and handle the case where the category doesn't exist.
* Make invites/requests separate from regular notifications (like a separate section of the notifications view on the client). Then, pull notifications but also pull invites.
* Premium user status is only verified client-side
* Premium usership should have teirs: perhaps $2.99/month unlocks the number of budget entries while $3.99/month unlocks number of entires *and* budget sharing
* Verify user age
* Warn a user that they cannot unshare a budget once it is shared
* Mention that buddy requests adn budget share invites will be deleted after 30 days
* Handle too many attempts for both sign in and change password
* Tell users that read-only budget users cannot modify or add entries to budgets or invite other users
* Client should not allow lower than a certain threshold of parameters for hashing (e.g. 14 iterations with 128mb of RAM, paralellism factor of 4, and a length of 32), no matter what the server says. This prevents attackers who infiltrate the server from obtaining the key with a low hash value. The app will not send any hash that doesn't meet the threshold.
* Upon logout (forced or manual), overwrite sensitive data.
* Synchronize all data with a hash. When client goes to update data, the client must provide a hash of the encrypted data that it thinks the server has. If the hash doesn't match what the server has, the update is rejected by the server. The client must pull what the server has and redo the update.
* Client icon should be iMessage-bubble blue
* Send user email in encrypted entry data (including edits) to track who created/updated budget entries. Allow user to add a name for email addresses he/she recognizes that will be stored with user preferences.
* Budget should store (in encrypted blob) a list of all users who have accepted the share of a budget. As soon as a user accepts a budget share, the user should update the budget to add themselves to that list.
* All encrypted fields should house encrypted JSON, even if that JSON has just a single field. This will allow those fields to be easily extensible and backwards compatible.
* App should send release version in a header
* Use RSA-4096 + Kyber-1024 for exchanging symmetric keys. The keys will be encrypted with RSA(Kyber(Key)). RSA-4096 is state-of-the-art and Kyber-1024 is quantum-resistant.
* `user_key_store` model on server should contain:
  - RSA private key
  - Private keys for accessing budgets
* Send version with every request. A response code should indicate that the client is too out-of-date to function properly. Notify the user that they need to update the app and only allow offline access.
* Client should add random data to their `user_keystore` of a random size (not greater than a megabyte) so the server cannot accurately estimate the number or budgets a user has based on the size of the encrypted blob.
* A budget invite does not have a foreign key constraint for the database. That means that the budget could be deleted while an invite is still active for the budget. If there is a 404 for the budget invite, display a message to the user that says something like "This budget no longer exists" and delete the invite.
* If budget share invite sender email == recipient email, do nothing when accepting budget
* The server can't easily validate that a budget invitation doesn't already exist for the recipient. The client should combine all budget share invites to the same budget into one to display to the user. Listing any one of the invite senders should be just fine.
* When a user goes to delete their data, show a warning that some user information will be temporarily visible on the server until the deletion is carried out. This information includes: 1) How many budgets a user is part of and 2) when these budgets were last edited. Other details about the budget will remain encrypted and unaccessible to the server.
* Mention that budgets that go unmodified for a year will be deleted
* Users need to be able to ignore specific email addresses that invite them to budgets (gets saved in user preferences)

#### IMPORTANT Data Syncronization Stuff
* Synchronize all data with a hash. When client goes to update data, the client must provide a hash of the encrypted data that it thinks the server has. If the hash doesn't match what the server has, the update is rejected by the server. The client must pull what the server has and redo the update.
* All data should have a `syncedTimestamp` or `synced_timestamp`. Data older than X minutes will get pulled from the server. The timestamp should be based on the server's time (on app startup, calculate a delta between the server time and the client's time (in UTC). Count the minutes the clock is off and use that delta to calculate the synced_timestamp. UPDATE THE DELTA UPON TOKEN REFRESH.
  - THIS DELTA SHOULD BE USED FOR CHECKING TOKEN EXPIRATIONS AS WELL.
* If the last synchronization with the server was more than one year ago (according to the server's time), all data needs to be deleted and pulled again. The server's `tombstone` table will be cleared of tombstones older than a year.

### End-to-end Encryption Scheme
* When a new user is created, an encryption key is randomly generated for the user *on the client*. This encryption key gets encrypted twice, once with a argon2 hash of the user's password (the server stores the salt for the hash; the salt for authentication can be requsted publicly, but if the server doesn't recognize the email address then a random salt is returned to disguise whether the email address exists in the system) and once with the a recovery key that is hashed in the same way. Both encryptions are stored on the server and sent to the client. The client can decrypt the user's encryption key (using their password) and store it securely (KeyChain, for example, guarded with FaceID).
* Recovery key is a 32-character alphanumeric string. It gets hashed with argon2 using a salt that is stored on the server. That hash is the key to decrypt the user's encryption key.
* Authentication string for sign in is a separate argon2 hash of the user's password with a different salt. This hash gets re-hashed (Argon2) before being stored in the database
* Encrypt user preferences using a user's key
* All user data (budgets, entries, user preferences, etc.) should be stored as an ID, associated_id (optional, e.g. a budget_id for an entry), a modified_timestamp, and an encrypted blob
  - Tombstones should still exist
* Each budget (along with its associated entries) has its own encryption key. These keys are encrypted with the user's own key and then synchronized with the server
* Encrypt user's private key using the user's password. Public key will be shared publicly along with user info (app version)
* Use RSA-4096 + Kyber-1024 for exchanging symmetric keys. The keys will be encrypted with RSA(Kyber(Key)). RSA-4096 is state-of-the-art and Kyber-1024 is quantum-resistant.
* When sending a budget share request, the budget's encryption key is encrypted with the recipient's public key. If the recipient accepts the invite, the server sends over the encrypted key (or just deletes the invitation and encrypted key if recipient declines). Both users save the encryption key (encrypting it with their own keys and synchronizing the encrypted keys with the server). The key gets saved in in the `user_budgets` table for the user.
  - Once the key is received, the client re-encrypts it with their ChaCha20-Poly1305 encryption key and replaces the RSA-encrypted key on the server.
* When changing password, everything needs to be re-uploaded. This ought to be done in a single request and a single databasse transaction (otherwise, the user's data could be left in an unrecoverable state)
* When a user leaves a budget share, they simply delete the key.
  - Perhaps send new key to all other users (and update key in budget_share_invite)
* To synchronize data, the server should send a list of existing IDs of a type (e.g. the IDs of all budgets a user belongs to) along with the `modified_timestamp`. The client can request data as needed. Tombstones should exist so user can check if data has been deleted.
* Things that aren't encrypted:
  - User's email address
* User ID, which is used to access user data, is kept private. In tokens that the user received, the user's email address and ID are encrypted.
* Client and server nonces for sign in
* Each budget has a list of Ed25519 public keys for users it allows access to. By proving it has the private key, a user can update the budget. To share a budget, a user signs a token (that expires 30 days later) that allows a user with a particular email to register for a budget and encrypts it with the receiver's key. The receiver generates a key pair and shares the public key with the server, certifying with the token that he/she has been invited to the budget. The server returns the budget encryption key that the sender has encrypted using the receiver's public key. When a client updates a budget, the client must send a token containing a UNIX timestamp for expiration, a user_id that specifies which user can use the token, a budget_id, and a key_id that is signed with the private key on the user's device and verified by the server using the public key that the server has (must match the key_id and budget_id).
* Verification of tokens and authentication strings uses comparison functions that are resistant to timing attacks.
* The server doesn't keep *any* unnecessary information about the user, not even the date the user signed up.
* Client should add random data to their `user_keystore` of a random size (not greater than a megabyte) so the server cannot accurately estimate the number or budgets a user has based on the size of the encrypted blob.
* The server doesn't keep track of who a budget invitation has come from or which budget the user has been invited to. Instead, a public Ed25519 key is associated with a budget. The inviting user sends the recipient the corresponding private key (encrypted using the recipient's public key) so the recipient can certify that he/she has been granted priviledges to access a budget upon accepting an invitation. The invitations expire, so an expiration is stored with each public share key. The invitations track only the month they were created in (not the year) so the server can delete invitations that are two or three months old without being able to associate the timestamp on the invitation with the timestamp of the public budget share key.
  - A sender can retract an invitation by signing a token that the server verifies came from the sender (the sender generates an Ed25519 key pair and gives the server the public key, which the server saves in the share invite)
* Note on what is possible: Though a review of our server source code will show that we do not record who has access to which budget, when a user retrieves or modifies a budget we see who the user is and which budget they have signed a token to access. It is, therefore, *technically* possible for us to capture that information and see which budgets a user is accessing. It is a promise that we make that we *will not* record this information, and we provide the server's source code to support our claims that we don't capture this data. We know of no way to restrict users' access to each other's budgets without some way of identifying the user. In our case, this identification happens when users reveal that they hold a private key certifying access to a budget by cryptographically signing a token. This token scheme allows users to prove to the server that they have exclusive access to a budget without us needing to store evidence of a relationship between a user and a budget in our database.
  - While it is technically possible for us to capture which budgets a user has access to, it is *not* possible for us to decrypt details about a budget or its entries. Those details are encrypted with a key that is only accessible with a user's password, which never leaves the user's device(s), not even during authentication.

### Minimum Viable Product

* Make sure unverified `users` table records get removed in a timely manner. This may require temporarily storing a user_created timestamp.
* Put foreign keys in tables in `up.sql`
* No need to enforce argon2 memory is a power of 2
* Budget endpoints should require a budget token AND an access token. Budget tokens signed with private RSA keys don’t identify a user but can only be generated if the user has the private key
  - Store budget keys (along with keys for signing token generation) as an encrypted JSON blob in a database table. Perhaps name it `user_keystore`.
* Blacklist only the hashes of tokens. Don't store the user_id associated with the token in the DB.
* Rename app to "Entries"
* If update comes for data that doesn’t exist, create it
* Limit public keys per budget to 200.
* Get rid of last_token_refresh_time. It isn't needed (because deleting user data without knowing which budgets the user owns isn't worth it) and is an unnecessary piece of data to know about a user.
  - Don't collect version either. The client will send version with every request. Handlers that require a specific minimum version can use the AppVersion middleware to check the version. A response code (perhaps 418 I'm A teapot) should indicate that the client is too out-of-date to properly handle the response the server will give.
* Get rid of user `created_timestamp` and `rsa_key_created_timestamp`.
* Send UNIX timestamp with refresh token
* Users remove themselves from budgets by removing their public key (must provide token verified with the public key they are removing, of course. If final public key is removed from a budget, the server deletes the entire budget.
* A user deletion request should include a list of public keys to remove from budgets.
* Each budget has a list of Ed25519 public keys for users it allows access to. By proving it has the private key, a user can update the budget. To share a budget, a user signs a token (that expires 30 days later) that allows a user with a particular email to register for a budget and encrypts it with the receiver's key. The receiver generates a key pair and shares the public key with the server, certifying with the token that he/she has been invited to the budget. The server returns the budget encryption key that the sender has encrypted using the receiver's public key. When a client updates a budget, the client must send a token containing a UNIX timestamp for expiration, a user_id that specifies which user can use the token, a budget_id, and a key_id that is signed with the private key on the user's device and verified by the server using the public key that the server has (must match the key_id and budget_id).
* Return codes with more information for the app (i.e. first few chars of response payload give more information about errors)
* Get rid of data tombstones and user tombstones! Use a field `deletion_date` that is null by default, unless the data has been deleted.
* Provide hashing parameters to client along with salt. The server should have a reasonable length limit on auth_strings before it chooses not to process them.
* Maximum of 40 people can be invited/joined to a budget. Unaccepted invites should expire after 1 week (use a timestamp to enforce this, but also create a cron job to clean out old invites).
* Throttle budget invites to 1 per second per user.
* In env.rs for budgetapp-server, rename `Conf` struct to `RawConf`. `build_conf()` should then crate a new `Conf` struct that has all the preprocessing done for fields that need it (such as the ChaCha key for tokens; a cipher should be initialized in env.rs with the key and then referred used for auth tokens). Validation can also be done (for example, ensuring the ChaCha key is the correct length)
  - Zeroize old RawConf memory for keys
* Ability to change encryption key. This should also log all other users out.
* TOTP Should *not* allow just expired or upcoming codes to be used. The must be a better solution.
* Different TOTP key per user for additional security (rotate with every sign in) stored as bytes in the DB
* Use a `signin_nonce` for both signing in with a password and verifying OTP.
* Never tell the client to hash with fewer than a certain number of iterations of argon2.
* Keys should all be specified in hex (and be of a specified length)
* Change Email endpoint (user must verify email)
* User sign in (and obtaining nonce) should mask when a user is not found
* For signing in with a password, require a nonce to prevent replay attacks.
* Create user nonce record when creating user (with a null nonce)
* Endpoint that returns authentication salt AND a server nonce (save the server nonce)
* Endpoints for getting and updating user_security_data
  - Password_encryption_salt and iters + encryption_key_user_password
  - Recovery data
  - Update data
* Change password via a token ("reset password"/"forgot password" instead of "change password")
* Throttle the "forgot password" endpoint. Create a record and make sure that emails can only be sent once every 30 minutes.
  - Schedule a job that clears out old records of forgot password endpoint hits
* Return error codes from the API with the message (i.e. a number indicating what the failure was). ServerError should take a code
* Clear `budget_share_invites` and `buddy_requests` that are greater than 30 days old
* For budgets, create a tombstone for every user that belongs to the budget (so related_user_id can be enforced)
* Try wrapping `web::Data` fields in a mutex or a `RefCell` so it can be zeroized (or just try making it mut)
* The server should check tombstones automatically if an item isn't found but is in the tombstone table and respond that the item has been deleted with an HTTP "410 Gone" (do this for the `user_tombstone` too). Make sure this only works with the proper authorization and user_id from a token.
* Tombstones should be cleared after 366 days
* Send the server's time in the heartbeat
* Create user endpoint must have an `acknowledge_agreement` field. If the field is false, the endpoint returns a 400 error
* Get email delivery set up (MailJet?)
  - OTP for sign in
  - OTP for change password
  - Forgot Password
  - OTP for forgot password
  - User creation verification
  - User deletion verification
  - Budget shared? Users need a way to turn off this notification
* Endpoint for changing user's encryption key (must re-encrypt user data and budget keys and get a new recovery key).
* RSA key rotation. Users must re-encrypt all budget_share_invites they've received using their new public key.
* Search through TODOs in code
* Unit tests!
* Update readme documentation
  - Add a section for the job scheduler
* White paper
* Should the app be renamed "Good Budgets"? "Simple Budgets"?
* Budgets that are not modified for a year will be deleted

### Do it later

* Perhaps use `typed_html` crate for HTML in user verification and deletion?
* When updating data in DAOs, combine checking the hash and updating the data into one query.
* Once NIST comes out with an official recommendation for a quantum-resistant algorithm, add another key pair with the new algorithm and begin double-encrypting and signing with the new quantum-resistant algorithm
* Add webauthn-rs and totp_rs
* Update crates (like base64)
* Change key when someone leaves budgets and send it, encrypted, to all others in budget
* Duplicate a budget, including entries (perhaps make including entries optional)
* When decoding tokens, use string views rather than splitting into separate strings
* Rotate users' RSA keys. Keep the old one on hand (and the date it was retired) for decrypting keys from current budget invitations
* Don't reach out to db as part of validating refresh token in the auth_token module. Instead, check blacklisted token explicitly from the handler
* Only get certain fields of a user or budget when requesting. i.e. use `SELECT field1, field2, etc WHERE ...` in query instead of `SELECT * WHERE ...`
* Handle all checks if user is in budget within the query being made
* Use more string slices to avoid extra allocations when creating structs. Use lifetimes to accomplish this
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
* Languages/localization

### Note on timezones

* Budget and entry dates are fixed. The timezone the user in is not relevant; the budgets will always end according to the date for the user. The client will likely use timezone data in the encrypted data it sends to the server
