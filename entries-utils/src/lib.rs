#![cfg(not(doctest))]

#[macro_use]
extern crate diesel;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;

#[cfg(test)]
mod test_env;

pub mod db;
pub mod email;
pub mod html;
pub mod messages;
pub mod models;
pub mod otp;
pub mod request_io;
pub mod schema;
pub mod token;
pub mod validators;
