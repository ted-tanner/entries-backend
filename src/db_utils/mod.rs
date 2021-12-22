pub mod user;

use chrono::Datelike;

use crate::env;
use crate::env::password::COMMON_PASSWORDS_TREE;
use crate::handlers::request_io::InputUser;

#[inline]
pub fn validate_email_address(email: &str) -> bool {
    for c in email.chars() {
        if c == ' ' || !c.is_ascii() {
            return false;
        }
    }

    if email.contains("@.") {
        return false;
    }

    let email = match email.split_once('@') {
        Some(s) => s,
        None => return false,
    };

    if email.0.len() == 0 || email.1.len() < 3 {
        return false;
    }

    if email.1.contains('@') || !email.1.contains('.') {
        return false;
    }

    if email.1.ends_with('.') {
        return false;
    }

    return true;
}

#[derive(Debug)]
pub enum PasswordValidity {
    VALID,
    INVALID(&'static str),
}

impl PasswordValidity {
    #[allow(dead_code)]
    pub fn is_valid(&self) -> bool {
        match &self {
            PasswordValidity::VALID => true,
            PasswordValidity::INVALID(_) => false,
        }
    }
}

#[inline]
pub fn validate_strong_password(user: &InputUser) -> PasswordValidity {
    // 12 is hardcoded because the common-passwords list assumes 12-character-long passwords
    if user.password.len() < 12 {
        return PasswordValidity::INVALID("Password must be at least 12 characters long.");
    }

    let lowercase_password = user.password.to_lowercase();

    if lowercase_password.contains(&env::APP_NAME.to_lowercase().replace(" ", "")) {
        return PasswordValidity::INVALID("Password must not contain the name of the app.");
    }

    if lowercase_password.contains("password") {
        return PasswordValidity::INVALID("Password must not contain the word \"password\"");
    }

    let mut contains_lowercase = false;
    let mut contains_uppercase = false;
    let mut contains_number = false;
    let mut contains_punct = false;

    for c in user.password.chars() {
        if !contains_lowercase && c.is_lowercase() {
            contains_lowercase = true;
            continue;
        }

        if !contains_uppercase && c.is_uppercase() {
            contains_uppercase = true;
            continue;
        }

        if !contains_number && c.is_numeric() {
            contains_number = true;
            continue;
        }

        if !contains_punct && c.is_ascii_punctuation() {
            contains_punct = true;
            continue;
        }
    }

    if !contains_lowercase {
        return PasswordValidity::INVALID("Password must contain at least one lowercase letter.");
    }

    if !contains_uppercase {
        return PasswordValidity::INVALID("Password must contain at least one uppercase letter.");
    }

    if !contains_number {
        return PasswordValidity::INVALID("Password must contain at least one number.");
    }

    if !contains_punct {
        return PasswordValidity::INVALID(
            "Password must contain at least one of the following: ! ? @ $ % - & + # * ( ) \" ' , . / : ; < = > [ \\ ] ^ _ { | } ~"
        );
    }

    if lowercase_password.contains(&user.first_name.to_lowercase()) {
        return PasswordValidity::INVALID("Password must not contain your first name.");
    }

    if lowercase_password.contains(&user.last_name.to_lowercase()) {
        return PasswordValidity::INVALID("Password must not contain your last name.");
    }

    let email_username = user.email.split_once('@').unwrap_or((&user.email, "")).0;
    if lowercase_password.contains(&email_username.to_lowercase()) {
        return PasswordValidity::INVALID("Password must not contain your email username.");
    }

    if user
        .password
        .contains(&user.date_of_birth.year().to_string())
    {
        return PasswordValidity::INVALID("Password must not contain your birth year.");
    }

    let current_year = chrono::Utc::now().year();
    let nearby_year_range = (current_year - 10)..=(current_year + 5);

    for year in nearby_year_range {
        if user.password.contains(&year.to_string()) {
            return PasswordValidity::INVALID(
                "Password must not contain a current, recent, or upcoming year.",
            );
        }
    }

    if COMMON_PASSWORDS_TREE.contains(&lowercase_password) {
        return PasswordValidity::INVALID(
            "Your password is too common. It was found on an online list of the 1,000,000 most commonly used passwords."
        );
    }

    PasswordValidity::VALID
}

#[cfg(test)]
mod test {
    use super::*;

    use chrono::NaiveDate;
    use rand::prelude::*;

    use crate::env;
    use crate::handlers::request_io::InputUser;

    #[test]
    fn test_validate_email_address() {
        // Valid
        const NORMAL: &'static str = "test@example.com";
        const WITH_DOT_IN_USERNAME: &'static str = "test.me@example.com";
        const MULTIPLE_DOT_DOMAIN: &'static str = "email@example.co.jp";
        const PLUS_IN_USERNAME: &'static str = "firstname+lastname@example.com";
        const IP_DOMAIN: &'static str = "email@123.123.123.123";
        const BRACKETED_IP_DOMAIN: &'static str = "email@[123.123.123.123]";
        const WITH_QUOTATION_MARKS: &'static str = "\"email\"@example.com";
        const NUMERIC_USERNAME: &'static str = "1234567890@example.com";
        const DASH_IN_DOMAIN: &'static str = "email@example-one.com";
        const DASH_IN_USERNAME: &'static str = "firstname-lastname@example.com";
        const ALL_UNDERSCORE_USERNAME: &'static str = "_______@example.com";

        assert!(validate_email_address(NORMAL));
        assert!(validate_email_address(WITH_DOT_IN_USERNAME));
        assert!(validate_email_address(MULTIPLE_DOT_DOMAIN));
        assert!(validate_email_address(PLUS_IN_USERNAME));
        assert!(validate_email_address(IP_DOMAIN));
        assert!(validate_email_address(BRACKETED_IP_DOMAIN));
        assert!(validate_email_address(WITH_QUOTATION_MARKS));
        assert!(validate_email_address(NUMERIC_USERNAME));
        assert!(validate_email_address(DASH_IN_DOMAIN));
        assert!(validate_email_address(DASH_IN_USERNAME));
        assert!(validate_email_address(ALL_UNDERSCORE_USERNAME));

        // Invalid
        const WITH_SPACE: &'static str = "te st@example.com";
        const NON_ASCII_CHAR: &'static str = "test😂@example.com";
        const MULTIPLE_AT: &'static str = "test@exam.com@ple.com";
        const NO_AT: &'static str = "testexample.com";
        const DOMAIN_DOT_ADJACENT_TO_AT: &'static str = "test@.com";
        const DOT_LAST_CHAR: &'static str = "test@example.com.";

        assert!(!validate_email_address(WITH_SPACE));
        assert!(!validate_email_address(NON_ASCII_CHAR));
        assert!(!validate_email_address(MULTIPLE_AT));
        assert!(!validate_email_address(NO_AT));
        assert!(!validate_email_address(DOMAIN_DOT_ADJACENT_TO_AT));
        assert!(!validate_email_address(DOT_LAST_CHAR));
    }

    #[test]
    fn test_validate_strong_password() {
        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
        let mut user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::new(),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1940..=1990),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        // Empty
        assert!(!validate_strong_password(&user).is_valid());

        // Shorter than 12 chars
        user.password = String::from("Qo1aG@Qe!9z");
        assert!(!validate_strong_password(&user).is_valid());

        // Contains app name
        user.password = String::from("&#AkG@Qe!^91z") + &(*env::APP_NAME).replace(" ", "") + "&45D";
        assert!(!validate_strong_password(&user).is_valid());

        // Contains "password"
        user.password = String::from("sd@#$#324dDPaSsWOrd#$90");
        assert!(!validate_strong_password(&user).is_valid());

        // No uppercase
        user.password = String::from("axgwjq7byvbgzu&70@1$");
        assert!(!validate_strong_password(&user).is_valid());

        // No lowercase
        user.password = String::from("XLX%J!6&$SAUYII2*Q4J");
        assert!(!validate_strong_password(&user).is_valid());

        // No number
        user.password = String::from("Hf)y!GqmiB&#Agwa*qbQ");
        assert!(!validate_strong_password(&user).is_valid());

        // No ASCII special chars
        user.password = String::from("aqBA19jyuajjq3UvpYwp");
        assert!(!validate_strong_password(&user).is_valid());

        // Contains user's first name
        user.password = String::from("yqTq8xAOJ$") + &user.first_name + "$d9";
        assert!(!validate_strong_password(&user).is_valid());

        // Contains user's last name
        user.password = String::from("8#@V2TT0or") + &user.last_name + "HF^h3z";
        assert!(!validate_strong_password(&user).is_valid());

        // Contains username part of user's email
        user.password =
            String::from("Qh*r4qj8vD") + user.email.split_once('@').unwrap().0 + "3uX#F";
        assert!(!validate_strong_password(&user).is_valid());

        // Contains user's birth year
        user.password =
            String::from("8#@V2TT0") + &user.date_of_birth.year().to_string() + "or)HF^h3z";
        assert!(!validate_strong_password(&user).is_valid());

        // Contains current or recent year
        user.password = String::from("wn0iVR2q2021#QiubXb");
        assert!(!validate_strong_password(&user).is_valid());

        // Common password
        user.password = String::from("abcd!EFG!123");
        assert!(!validate_strong_password(&user).is_valid());

        // Valid
        user.password = String::from("1&B3d^hJ37^9$YNA2sD9");
        assert!(validate_strong_password(&user).is_valid());

        // Valid
        user.password = String::from("HtbNUF4j&x92");
        assert!(validate_strong_password(&user).is_valid());
    }
}
