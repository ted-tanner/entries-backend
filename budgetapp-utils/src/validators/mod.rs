use chrono::Datelike;

use crate::common_password_set::CommonPasswordSet;

#[derive(Debug)]
pub enum Validity {
    Valid,
    Invalid(&'static str),
}

impl Validity {
    #[allow(dead_code)]
    pub fn is_valid(&self) -> bool {
        match &self {
            Validity::Valid => true,
            Validity::Invalid(_) => false,
        }
    }
}

pub fn validate_email_address(email: &str) -> Validity {
    for c in email.chars() {
        if c == ' ' || !c.is_ascii() {
            return Validity::Invalid("Email address cannot contain a space.");
        }
    }

    if email.contains("@.") {
        return Validity::Invalid("Domain name in email address cannot begin with a period.");
    }

    let email = match email.split_once('@') {
        Some(s) => s,
        None => return Validity::Invalid("Email address must contain an at symbol (@)."),
    };

    if email.0.is_empty() || email.1.len() < 3 {
        return Validity::Invalid("Email username or domain name is to short.");
    }

    if email.1.contains('@') || !email.1.contains('.') {
        return Validity::Invalid(
            "Email address must have only one at symbol (@) and the domain must contain a period.",
        );
    }

    if email.1.ends_with('.') {
        return Validity::Invalid("Email address cannot end with a period.");
    }

    Validity::Valid
}

pub fn validate_strong_password(
    password: &str,
    email: &str,
    first_name: &str,
    last_name: &str,
    date_of_birth: &chrono::NaiveDate,
    app_name: &str,
    common_passwords: &CommonPasswordSet,
) -> Validity {
    // 12 is hardcoded because the common-passwords list assumes 12-character-long passwords
    if password.len() < 12 {
        return Validity::Invalid("Password must be at least 12 characters long.");
    }

    let lowercase_password = password.to_lowercase();

    if lowercase_password.contains(&app_name.to_lowercase().replace(' ', ""))
        || lowercase_password.contains(&app_name.to_lowercase())
    {
        return Validity::Invalid("Password must not contain the name of the app.");
    }

    if lowercase_password.contains("password") {
        return Validity::Invalid("Password must not contain the word \"password.\"");
    }

    let mut contains_lowercase = false;
    let mut contains_uppercase = false;
    let mut contains_number = false;
    let mut contains_punct = false;

    for c in password.chars() {
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
        return Validity::Invalid("Password must contain at least one lowercase letter.");
    }

    if !contains_uppercase {
        return Validity::Invalid("Password must contain at least one uppercase letter.");
    }

    if !contains_number {
        return Validity::Invalid("Password must contain at least one number.");
    }

    if !contains_punct {
        return Validity::Invalid(
            "Password must contain at least one of the following: ! ? @ \
             $ % - & + # * ( ) \" ' , . / : ; < = > [ \\ ] ^ _ { | } ~",
        );
    }

    if lowercase_password.contains(&first_name.to_lowercase()) {
        return Validity::Invalid("Password must not contain your first name.");
    }

    if lowercase_password.contains(&last_name.to_lowercase()) {
        return Validity::Invalid("Password must not contain your last name.");
    }

    let email_username = email.split_once('@').unwrap_or((email, "")).0;
    if lowercase_password.contains(&email_username.to_lowercase()) {
        return Validity::Invalid("Password must not contain your email username.");
    }

    if password.contains(&date_of_birth.year().to_string()) {
        return Validity::Invalid("Password must not contain your birth year.");
    }

    let current_year = chrono::Utc::now().year();
    let nearby_year_range = (current_year - 10)..=(current_year + 5);

    for year in nearby_year_range {
        if password.contains(&year.to_string()) {
            return Validity::Invalid(
                "Password must not contain a current, recent, or upcoming year.",
            );
        }
    }

    if common_passwords.contains(password) {
        return Validity::Invalid(
            "Your password is too common. It was found on an online list of the 1,000,000 most commonly used passwords."
        );
    }

    Validity::Valid
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::NaiveDate;
    use rand::prelude::*;

    #[actix_rt::test]
    async fn test_validate_email_address() {
        // Valid
        const NORMAL: &str = "test@example.com";
        const WITH_DOT_IN_USERNAME: &str = "test.me@example.com";
        const MULTIPLE_DOT_DOMAIN: &str = "email@example.co.jp";
        const PLUS_IN_USERNAME: &str = "firstname+lastname@example.com";
        const IP_DOMAIN: &str = "email@123.123.123.123";
        const BRACKETED_IP_DOMAIN: &str = "email@[123.123.123.123]";
        const WITH_QUOTATION_MARKS: &str = "\"email\"@example.com";
        const NUMERIC_USERNAME: &str = "1234567890@example.com";
        const DASH_IN_DOMAIN: &str = "email@example-one.com";
        const DASH_IN_USERNAME: &str = "firstname-lastname@example.com";
        const ALL_UNDERSCORE_USERNAME: &str = "_______@example.com";

        assert!(validate_email_address(NORMAL).is_valid());
        assert!(validate_email_address(WITH_DOT_IN_USERNAME).is_valid());
        assert!(validate_email_address(MULTIPLE_DOT_DOMAIN).is_valid());
        assert!(validate_email_address(PLUS_IN_USERNAME).is_valid());
        assert!(validate_email_address(IP_DOMAIN).is_valid());
        assert!(validate_email_address(BRACKETED_IP_DOMAIN).is_valid());
        assert!(validate_email_address(WITH_QUOTATION_MARKS).is_valid());
        assert!(validate_email_address(NUMERIC_USERNAME).is_valid());
        assert!(validate_email_address(DASH_IN_DOMAIN).is_valid());
        assert!(validate_email_address(DASH_IN_USERNAME).is_valid());
        assert!(validate_email_address(ALL_UNDERSCORE_USERNAME).is_valid());

        // Invalid
        const WITH_SPACE: &str = "te st@example.com";
        const NON_ASCII_CHAR: &str = "test😂@example.com";
        const MULTIPLE_AT: &str = "test@exam.com@ple.com";
        const NO_AT: &str = "testexample.com";
        const DOMAIN_DOT_ADJACENT_TO_AT: &str = "test@.com";
        const DOT_LAST_CHAR: &str = "test@example.com.";

        assert!(!validate_email_address(WITH_SPACE).is_valid());
        assert!(!validate_email_address(NON_ASCII_CHAR).is_valid());
        assert!(!validate_email_address(MULTIPLE_AT).is_valid());
        assert!(!validate_email_address(NO_AT).is_valid());
        assert!(!validate_email_address(DOMAIN_DOT_ADJACENT_TO_AT).is_valid());
        assert!(!validate_email_address(DOT_LAST_CHAR).is_valid());
    }

    #[actix_rt::test]
    async fn test_validate_strong_password() {
        const EMAIL: &str = "test_user@test.com";
        const FIRST_NAME: &str = "Arnold";
        const LAST_NAME: &str = "Schwarzenegger";

        let date_of_birth = NaiveDate::from_ymd_opt(
            rand::thread_rng().gen_range(1940..=1990),
            rand::thread_rng().gen_range(1..=12),
            rand::thread_rng().gen_range(1..=28),
        )
        .unwrap();

        let mut password = String::new();

        // Empty
        assert!(
            !validate_strong_password(&password, EMAIL, FIRST_NAME, LAST_NAME, &date_of_birth)
                .is_valid()
        );

        // Shorter than 12 chars
        password = String::from("Qo1aG@Qe!9z");
        assert!(
            !validate_strong_password(&password, EMAIL, FIRST_NAME, LAST_NAME, &date_of_birth)
                .is_valid()
        );

        // Contains app name with space
        password = String::from("&#AkG@Qe!^91z") + (*env::APP_NAME) + "&45D";
        assert!(
            !validate_strong_password(&password, EMAIL, FIRST_NAME, LAST_NAME, &date_of_birth)
                .is_valid()
        );

        // Contains app name without space
        password = String::from("&#AkG@Qe!^91z") + &(*env::APP_NAME).replace(' ', "") + "&45D";
        assert!(
            !validate_strong_password(&password, EMAIL, FIRST_NAME, LAST_NAME, &date_of_birth)
                .is_valid()
        );

        // Contains "password"
        password = String::from("sd@#$#324dDPaSsWOrd#$90");
        assert!(
            !validate_strong_password(&password, EMAIL, FIRST_NAME, LAST_NAME, &date_of_birth)
                .is_valid()
        );

        // No uppercase
        password = String::from("axgwjq7byvbgzu&70@1$");
        assert!(
            !validate_strong_password(&password, EMAIL, FIRST_NAME, LAST_NAME, &date_of_birth)
                .is_valid()
        );

        // No lowercase
        password = String::from("XLX%J!6&$SAUYII2*Q4J");
        assert!(
            !validate_strong_password(&password, EMAIL, FIRST_NAME, LAST_NAME, &date_of_birth)
                .is_valid()
        );

        // No number
        password = String::from("Hf)y!GqmiB&#Agwa*qbQ");
        assert!(
            !validate_strong_password(&password, EMAIL, FIRST_NAME, LAST_NAME, &date_of_birth)
                .is_valid()
        );

        // No ASCII special chars
        password = String::from("aqBA19jyuajjq3UvpYwp");
        assert!(
            !validate_strong_password(&password, EMAIL, FIRST_NAME, LAST_NAME, &date_of_birth)
                .is_valid()
        );

        // Contains user's first name
        password = String::from("yqTq8xAOJ$") + FIRST_NAME + "$d9";
        assert!(
            !validate_strong_password(&password, EMAIL, FIRST_NAME, LAST_NAME, &date_of_birth)
                .is_valid()
        );

        // Contains user's last name
        password = String::from("8#@V2TT0or") + LAST_NAME + "HF^h3z";
        assert!(
            !validate_strong_password(&password, EMAIL, FIRST_NAME, LAST_NAME, &date_of_birth)
                .is_valid()
        );

        // Contains username part of user's email
        password = String::from("Qh*r4qj8vD") + EMAIL.split_once('@').unwrap().0 + "3uX#F";
        assert!(
            !validate_strong_password(&password, EMAIL, FIRST_NAME, LAST_NAME, &date_of_birth)
                .is_valid()
        );

        // Contains user's birth year
        password = String::from("8#@V2TT0") + &date_of_birth.year().to_string() + "or)HF^h3z";
        assert!(
            !validate_strong_password(&password, EMAIL, FIRST_NAME, LAST_NAME, &date_of_birth)
                .is_valid()
        );

        // Contains current or recent year
        password = String::from("wn0iVR2q2021#QiubXb");
        assert!(
            !validate_strong_password(&password, EMAIL, FIRST_NAME, LAST_NAME, &date_of_birth)
                .is_valid()
        );

        // Common password
        password = String::from("abcd!EFG!123");
        assert!(
            !validate_strong_password(&password, EMAIL, FIRST_NAME, LAST_NAME, &date_of_birth)
                .is_valid()
        );

        // Valid
        password = String::from("1&B3d^hJ37^9$YNA2sD9");
        assert!(
            validate_strong_password(&password, EMAIL, FIRST_NAME, LAST_NAME, &date_of_birth)
                .is_valid()
        );

        // Valid
        password = String::from("HtbNUF4j&x92");
        assert!(
            validate_strong_password(&password, EMAIL, FIRST_NAME, LAST_NAME, &date_of_birth)
                .is_valid()
        );
    }
}
