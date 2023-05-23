#![cfg(not(doctest))]

#[macro_use]
extern crate diesel;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;

mod argon2;

#[cfg(test)]
mod test_env;

pub mod argon2_hasher;
pub mod db;
pub mod email;
pub mod html;
pub mod models;
pub mod request_io;
pub mod schema;
pub mod token;
pub mod validators;
