use std::collections::BTreeSet;
use std::fs::File;
pub(crate) use std::io::{self, BufRead};

use crate::env;

pub struct CommonPasswordTree(BTreeSet<String>);

impl CommonPasswordTree {
    pub fn generate() -> CommonPasswordTree {
        let path = std::path::Path::new(*env::password::COMMON_PASSWORDS_FILE_PATH);

        let common_passwords_file = File::open(path).expect(
            format!(
                "Failed to open {}",
                path.to_str()
                    .unwrap_or(*env::password::COMMON_PASSWORDS_FILE_PATH)
            )
            .as_str(),
        );

        let mut tree = BTreeSet::<String>::new();

        if let Ok(lines) = read_lines_from_file(common_passwords_file) {
            for password in lines {
                if let Ok(password) = password {
                    tree.insert(password.to_string().to_lowercase());
                }
            }
        }

        CommonPasswordTree(tree)
    }

    pub fn contains(&self, password: &str) -> bool {
        self.0.contains(password)
    }
}

fn read_lines_from_file(file: File) -> io::Result<io::Lines<io::BufReader<File>>> {
    Ok(io::BufReader::new(file).lines())
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::prelude::*;

    #[test]
    fn test_common_password_tree() {
        let tree = CommonPasswordTree::generate();

        let path = std::path::Path::new(*env::password::COMMON_PASSWORDS_FILE_PATH);
        let common_passwords_file = File::open(path).unwrap();
        let common_passwords = io::BufReader::new(common_passwords_file)
            .lines()
            .filter_map(io::Result::ok)
            .map(|password| password.to_lowercase())
            .collect::<Vec<String>>();

        assert_ne!(common_passwords.len(), 0);

        let mut rng = rand::thread_rng();

        for _ in 0..10 {
            let password_idx = rng.gen_range(0..common_passwords.len());
            let password = &common_passwords[password_idx];

            debug_assert!(
                tree.contains(&password),
                "Tree should have contained password, but did not: {}",
                &password
            );
        }

        debug_assert!(
            tree.contains("password1234"),
            "Tree should have contained password, but did not: password1234"
        );

        assert!(!tree.contains("&!zatug"));
        assert!(!tree.contains("r6&vh0d60a&hvb"));
        assert!(!tree.contains("yptnmontq9f@%ije7z45"));
    }
}
