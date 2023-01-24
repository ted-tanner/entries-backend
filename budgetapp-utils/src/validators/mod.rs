#[derive(Debug)]
pub enum Validity {
    Valid,
    Invalid(String),
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
    if email.chars().count() > 320 {
        return Validity::Invalid(String::from("Email address cannot contain a space."));
    }

    for c in email.chars() {
        if c == ' ' || !c.is_ascii() {
            return Validity::Invalid(String::from("Email address cannot contain a space."));
        }
    }

    if email.contains("@.") {
        return Validity::Invalid(String::from(
            "Domain name in email address cannot begin with a period.",
        ));
    }

    let email = match email.split_once('@') {
        Some(s) => s,
        None => {
            return Validity::Invalid(String::from("Email address must contain an at symbol (@)."))
        }
    };

    if email.0.is_empty() || email.1.len() < 3 {
        return Validity::Invalid(String::from("Email username or domain name is to short."));
    }

    if email.1.contains('@') || !email.1.contains('.') {
        return Validity::Invalid(String::from(
            "Email address must have only one at symbol (@) and the domain must contain a period.",
        ));
    }

    if email.1.ends_with('.') {
        return Validity::Invalid(String::from("Email address cannot end with a period."));
    }

    Validity::Valid
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{distributions::Alphanumeric, Rng};

    #[test]
    fn test_validate_email_address() {
        // Valid
        const NORMAL: &str = "test@example.com";
        const WITH_DOT_IN_USERNAME: &str = "test.me@example.com";
        const MULTIPLE_DOT_DOMAIN: &str = "email@example.co.jp";
        const PLUS_IN_USERNAME: &str = "firstname+lastname@example.com";
        const IP_DOMAIN: &str = "email@123.123.123.123";
        const BRACKETED_IP_DOMAIN: &str = "email@[123.123.123.123]";
        const WITH_QUOTATION_MARKS: &str = "\"email\"@example.com";
        const NUMERIC_USERNAME: &str = "1234567890@example.co.uk";
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
        let mut too_long: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(255)
            .map(char::from)
            .collect();

        too_long.push('@');
        too_long.push_str(
            "thisisareallyreallylongdomainnamethatwillmaketheaddressinvalidbecauseitisjustlong",
        );
        too_long.push_str(".com");

        const WITH_SPACE: &str = "te st@example.com";
        const NON_ASCII_CHAR: &str = "test😂@example.com";
        const MULTIPLE_AT: &str = "test@exam.com@ple.com";
        const NO_AT: &str = "testexample.com";
        const DOMAIN_DOT_ADJACENT_TO_AT: &str = "test@.com";
        const DOT_LAST_CHAR: &str = "test@example.com.";

        assert!(!validate_email_address(&too_long).is_valid());
        assert!(!validate_email_address(WITH_SPACE).is_valid());
        assert!(!validate_email_address(NON_ASCII_CHAR).is_valid());
        assert!(!validate_email_address(MULTIPLE_AT).is_valid());
        assert!(!validate_email_address(NO_AT).is_valid());
        assert!(!validate_email_address(DOMAIN_DOT_ADJACENT_TO_AT).is_valid());
        assert!(!validate_email_address(DOT_LAST_CHAR).is_valid());
    }
}
