# The Budget App (Server)

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

    For macOS, don't install PostgreSQL via Homebrew. There are some issues with the Homebrew installation (since version 12) that can cause Postgres to stop working.

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
    CREATE ROLE username WITH createdb LOGIN PASSWORD '[password]';
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

* `redis_uri`

  The URI used to connect to Redis.

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

* `jwt_signing_key`

  Key used for signing JSON Web Tokens.

### Lifetimes

These configurations describe how long tokens last before being considered invalid.

* `access_token_lifetime_mins`

  The amount of time for which access tokens will be valid, in minutes.  The access token gets sent by the client with every request that needs to be authenticated. Because of the repeated usage of this token, it should be invalided quickly to prevent attackers who obtain the token from retaining sustained access.

* `otp_lifetime_mins`

  The amount of time for which TOTP codes will be valid. Also half the maximum amount of time for which siginin tokens will be valid.

  The server issues passcodes that are valid `otp_lifetime_mins` in the future to prevent user access from expiring imediately after a code is issued when the time interval lapses. The server will accept a current code or a code slightly in the future such that a user who is issued a code just before the completion of a time interval will have a working code for `otp_lifetime_mins` whereas a user who is issued a code just *after* the completion of a time interval will have a working code for `2 * otp_lifetime_mins`.

  Failed passcode attempts by a user are recorded and limited to prevent brute-forcing the code (see the `otp_max_attempts` configuration).

* `refresh_token_lifetiime_days`

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

To authenticate, send a JWT access token in the `Authorization` header:

```
curl -X GET "http://localhost:9000/api/user/get" -H "Authorization: Bearer [ACCESS_TOKEN]"
```

To refresh a JWT access token, you need to use a JWT refresh token (you should get it upon login):

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

To make a production build with -O3 optimizations as well as LTO (link-time optimization), run:

```
cargo build --profile production
```

These build flags also work with other commands such as `cargo test` and `cargo run`. Debug builds tend to take about half as long as release builds. LLVM is still LLVM when compiling Rust instead of C++, so link time optimization will still take a long, long time.

## Checking your Code

Rust takes a freakishly long time to compile. Here's my recommendation: don't. Instead of using `cargo run` or `cargo build`, use the following:

```
cargo check
```

`cargo check` runs the lexical analyzer, the parser, and the borrow-checker. The borrow-checker is Rust's secret sauce for memory safety. Because Rust has this immediate step to compilation, it can't parse directly to LLVM IR; the lexical analyzer outputs a high-level IR representing the abstract syntax tree. The parser transforms the high-level IR into a different IR which then gets run through the borrow-checker and subsequently parsed to LLVM IR. Long story short, all of that front-end stuff still has to happen with `cargo check`, so it can still take a long time. It will not, however, pass the generated LLVM IR to LLVM for optimization or machine code generation so there is still a significant chunk of time that gets shaved off by using `cargo check`.  

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

### Minimum Viable Product

* Try connecting to Redis on server startup just for verification purposes
* Get email delivery set up
  * OTP
  * Forgot Password
* Forgot password endpoint
* Verify SQL injection is not possible with any endpoint

### Do It Later

* Create integer error codes in an enum (EXPIRED, INVALID, INCORRECT_FORMAT, etc.)
* Fix Docker environment
* Pool Redis connections
* Clean up `main()`
* Use more string slices to avoid extra allocations when creating structs
* Create a method of encrypting data in the database
* Save all refresh tokens belonging to a user (save them when they get issued) in the database so they can all be blacklisted at once
