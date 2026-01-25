# Entries App (Backend)

## Contents

- [Dependencies](#dependencies)
- [Dev Dependencies](#dev-dependencies)
- [Setup](#setup)
  - [PostgreSQL Setup](#postgresql-setup)
  - [Diesel Migrations](#diesel-migrations)
  - [Compilation Requirements](#compilation-requirements)
- [Server Configuration](#server-configuration)
- [Running the Server](#running-the-server)
  - [Command-line Arguments](#command-line-arguments)
- [Job Scheduler](#job-scheduler)
  - [Configuration](#job-scheduler-configuration)
- [Testing the Server](#testing-the-server)
  - [Unit and Integration Tests](#unit-and-integration-tests)
- [Building the Server](#building-the-server)
- [Checking your Code](#checking-your-code)
- [To Do](#to-do)
  - [Minimum Viable Product](#minimum-viable-product)
  - [Do It Later](#do-it-later)

## Dependencies

1. PostgreSQL (17.5)

    [Download PostgreSQL here](https://postgresapp.com)

## Dev Dependencies

1. Rust Toolchain (Latest stable, edition 2021)

    [Installation instructions can be found here](https://www.rust-lang.org/tools/install)

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
    CREATE ROLE [username] WITH createdb LOGIN ENCRYPTED PASSWORD '[password]';
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
CREATE USER entriesdbuser WITH ENCRYPTED PASSWORD '[password]';
ALTER USER entriesdbuser CREATEDB;
CREATE DATABASE entries OWNER entriesdbuser ENCODING UTF8;
```

Obviously, for production the password should be something that doesn't suck

### Diesel Migrations

**WARNING:*** Be extremely cautious when running migrations. Migrations may cause data loss.

The server uses an ORM called Diesel.

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

### Compilation Requirements

To compile the project, you'll need to install the following dependencies:

```bash
# Install Protocol Buffers compiler
brew install protobuf

# Install PostgreSQL client libraries
brew install libpq

# Force link the PostgreSQL libraries
brew link --force libpq

# Set the PostgreSQL library directory environment variable
export PQ_LIB_DIR="$(brew --prefix libpq)/lib"
```

## Server Configuration

Configurations and secrets are read from environment variables. See the `sample.env` in each `entries-server` and `entries-job-scheduler` for all possible configs.

## Running the Server

To run the server via Cargo, the following commands can be used:

```
# Debug mode
cargo run

# Release mode
cargo run --release
```

See the [Command-line Argments](#command-line-arguments) section below for a list of available arguments that can be passed to the executable.

### Command-line Arguments

The server accepts a number of command-line arguments to change default behavior. Available arguments are listed below:

* `--port [NUMBER]`

  Specifies the port to run the HTTP server on. Defaults to `9000`.

  ##### Example
  ```
  ./entries-server --port 9002
  ```

## Job Scheduler

The project includes a job scheduler component that handles various background tasks such as cleaning up expired data and managing user accounts.

### Job Scheduler Configuration

The job scheduler configuration is handled through environment variables. See the `sample.env` file in the `entries-job-scheduler` directory for all available configuration options.

## Testing the Server

### Unit and Integration Tests

Unit and integration tests are run by `cargo`. They will fail if they are missing needed configurations or if they cannot connect to Postgres. It is recommended to have a test DB and configuration for running the tests.

To run the tests, make sure the environment is properly configured and running and run the following command:

```
cargo test
```

Some of the tests may perform actions (such as truncating a table) that can interfere with other tests. By default, these tests are ignored. To run *all* of the tests, use the following:

```
cargo test -- --include-ignored --test-threads=1
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

"Clippy" is the name of the linter being used for this project.

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

* Remember that users can change their email addresses. Email addresses stored in E2EE blobs may become invalid
* When sending bytes, consider endianness
* Before user leaves budget, check if user is the only user with write priviledges. If so, suggest to user that they give someone write priviledges before leaving the budget
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
* Use RSA-3172 + Kyber-1024 for exchanging symmetric keys. The keys will be encrypted with RSA(Kyber(Key)). RSA-3172 is state-of-the-art and Kyber-1024 is quantum-resistant.
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
* Maximum of 512 characters in a password
* Client should handle all the "throttle" cases with a nice message explaining the user needs to wait
* When an action will send an email (e.g. creating account, signing in, deleting account, etc.), tell users to check their spam box
* Limit description fields to 400 chars
* Recovery key should be 24 capital alphanumeric chars (e.g. WJAZ-Y0G1-B1H8-Q58Z-Q9BX-NYFK).

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
* Use RSA-3172 + Kyber-1024 for exchanging symmetric keys. The keys will be encrypted with RSA(Kyber(Key)). RSA-3172 is state-of-the-art and Kyber-1024 is quantum-resistant.
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
* To prevent revealing which email addresses use our service in the endpoint for obtaining the auth string hashing parameters, we return phony data when a user is not found. This phony data needs to change infrequently to adequately mimic a user's nonce. This is done by seeding a random number generator with the number of days since the unix epoch and then hashing the random number with the email address from the request. The nonce is a masked-off portion of the hash. To prevent timing attacks, this hashing takes place with every request to this endpoint regardless of whether or not it will be used.


### Minimum Viable Product

* Endpoint for uploading ALL data when creating an account (after using the app without an account for a while)
  - All objects, with entries and categories
  - user_keystore and user_prefs
  - Must be after user is verified. Perhaps after first login?
* Loosen up a tad on the create account limiting. Users may need multiple attempts and creating an account is one of the initial impressions a user receives.

### Do it later

* Description of EE2E scheme
* Get rid of created_timestamp on users table and use the UUIdv7 instead
  - The one place the timestamp matters is when clearing unverified users. Use the timestamp in the UUIDv7 to filter these
* Make limiter configurable by endpoint
* Remove OpenSSL (use Rust hmac, ed25519_dalek, sha1, etc instead)
  - Is there a good reason to do this?
* Once this PR is done and merged, use it in `Token::decode()` https://github.com/rust-lang/rust/pull/112818
* Accept SSL connections without reverse proxy, if no customers are really using
* Add webauthn-rs and totp_rs
* Update ed25519-dalek crate
* Enable serde `"rc"` feature and accept an `Arc<str>` (or perhaps `Rc<str>`) instead of a `String` for inputs (same with `Arc<[u8]>` instead of `Vec<u8>`)
* Endpoint for changing user's encryption key (must re-encrypt user data and budget keys and get a new recovery key.) This should also log all other devices out.
* Once NIST comes out with an official recommendation for a quantum-resistant algorithm, add another key pair with the new algorithm and begin double-encrypting and signing with the new quantum-resistant algorithm
* Rotate users' RSA keys. Keep the old one on hand (and the date it was retired) for decrypting keys from current budget invitations
* Update crates (like base64)
* Get rid of last_token_refresh_time. It isn't needed and is an unnecessary piece of data to know about a user.
  - Don't collect version either. The client will send version with every request. Handlers that require a specific minimum version can use the AppVersion middleware to check the version. A response code (perhaps 418 I'm A teapot) should indicate that the client is too out-of-date to properly handle the response the server will give.
* Perhaps use `typed_html` crate for HTML in user verification and deletion?
* When updating data in DAOs, combine checking the hash and updating the data into one query.
* Change key when someone leaves budgets and send it, encrypted, to all others in budget
* Change Email endpoint (user must verify email)
* Duplicate a budget, including entries (perhaps make including entries optional)
* When decoding tokens, use string views rather than splitting into separate strings
* Don't reach out to db as part of validating refresh token in the auth_token module. Instead, check blacklisted token explicitly from the handler
* Only get certain fields of a user or budget when requesting. i.e. use `SELECT field1, field2, etc WHERE ...` in query instead of `SELECT * WHERE ...`
* Handle all checks if user is in budget within the query being made
* Use more string slices to avoid extra allocations when creating structs. Use lifetimes to accomplish this
* Budget comments, entry comments
  - Reactions to said comments
* Validation for `entries_common::password_hasher::HashParams` (e.g. make sure `hash_mem_size_kib` is at least 128 and is a power of 2)
* Use lifetimes to reduce they copying of strings (e.g. TokenPair, TokenClaims, perhaps some of the OutputX structs, etc)
* Budget user get request logic should be handled in a query to eliminate multiple queries
* Create mock in Dao to test DB stuff in entries-common
* Replace lazy_static with OnceCell
* Save all refresh tokens belonging to a user (save them when they get issued) in the database so they can all be blacklisted at once.
* In `entries_server::handlers::budget::remove_budget(...)`, make deleting the budget non-blocking. Users have already been removed from the budget, so the handler can return without finishing deleting the budget. See the comment in the code for an idea of how to do this performantly
* OTP attempts, password attempts, and blacklisted tokens can be moved to Redis
* Comments (budget comments, entry comments, etc.)
* Publicly export models (so imports look like this `use crate::models::BuddyRequest;` rather than `use crate::models::buddy_request::BuddyRequest;`
* To ensure user is in budget, don't make db query. Just filter db items using a join with the UserBudgetAssociation
* Reject accept/decline budget shares and buddy requests if already accepted or declined
* Admin console
* If user deletion fails, put a record in another table for manual deletion later. When implementing this, make sure in `entries_common::db::user::delete_user` the request gets deleted from the requests table before attempting to delete user data so the request doesn't get run again in subsequent runs of the delete_users job.
* Give the job scheduler a thread pool and queue up jobs for the pool to execute so multiple jobs can run at once
* Languages/localization
* Budgets that are not modified for a year will be deleted?
* Full endpoint documentation
* Should limiter sometimes be user-based? Some endpoints cannot be user based, but those that can be maybe should be
* On client: Enforce practical limits on entries per budget and budgets per user
  - 5,000 budgets/user
  - 2,500 entries/budget
  - Client will limit description fields to 600 chars

### Note on timezones

* Budget and entry dates are fixed. The timezone the user in is not relevant; the budgets will always end according to the date for the user. The client will likely use timezone data in the encrypted data it sends to the server
