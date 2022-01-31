# The Budget App (Server)

## Contents

1. [Dependencies](#dependencies)
2. [Dev Dependencies](#dev-dependencies)
3. [Setup](#setup)
   1. [PostgreSQL Setup](#postgresql-setup)
   2. [Diesel Migrations](#diesel-migrations)
   3. [Redis Setup](#redis-setup)
4. [Server Configuration](#server-configuration)
5. [Running the Server](#running-the-server)
   1. [Files Needed by the Server](#files-needed-by-the-server)
   2. [Commmand-line Arguments](#command-line-arguments)
6. [Testing the Server](#testing-the-server)
   1. [Unit and Integration Tests](#unit-and-integration-tests)
   2. [Manual Testing](#manual-testing)
7. [Building the Server](#building-the-server)
8. [Checking your Code](#checking-your-code)
9. [To Do](#to-do)
   1. [Minimum Viable Product](#minimum-viable-product)
   2. [Do It Later](#do-it-later)

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

TODO

### Redis Setup

Redis should pretty much work of the box, but you might like to add a password (especially in a production environment). Redis passwords are hashed quickly and therefore easily brute forced, so the password in production needs to be long and random.

With the Redis server running (run `redis-server`), open the Redis CLI (run `redis-cli`) and enter the following:

```
CONFIG SET requirepass "[password]"
```

## Server Configuration

TODO

## Running the Server

TODO (how to run from `cargo` and from binary)

### Files Needed by the Server

TODO (include what needs to be in CWD, like `assets/common-passwords.txt` and `conf/budgetapp.toml`)

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
