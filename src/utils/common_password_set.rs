use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead};

use crate::env;

pub struct CommonPasswordSet(HashSet<String>);

impl CommonPasswordSet {
    pub fn generate() -> CommonPasswordSet {
        let path = std::path::Path::new(*env::password::COMMON_PASSWORDS_FILE_PATH);

        let file_error_msg = format!(
            "Failed to open {}",
            path.to_str()
                .unwrap_or(*env::password::COMMON_PASSWORDS_FILE_PATH)
        );
        let common_passwords_file = File::open(path).expect(&file_error_msg);

        let mut set = HashSet::<String>::new();

        if let Ok(lines) = read_lines_from_file(common_passwords_file) {
            for password in lines.flatten() {
                set.insert(password.to_string());
            }
        }

        CommonPasswordSet(set)
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

    #[actix_rt::test]
    async fn test_common_password_set() {
        let set = CommonPasswordSet::generate();
        
        let path = std::path::Path::new(*env::password::COMMON_PASSWORDS_FILE_PATH);
        let common_passwords_file = File::open(path).unwrap();
        let common_passwords = io::BufReader::new(common_passwords_file)
            .lines()
            .filter_map(io::Result::ok)
            .collect::<Vec<String>>();

        assert_ne!(common_passwords.len(), 0);

        let mut rng = rand::thread_rng();

        for _ in 0..10 {
            let password_idx = rng.gen_range(0..common_passwords.len());
            let password = &common_passwords[password_idx];

            debug_assert!(
                set.contains(password),
                "Set should have contained password, but did not: {}",
                &password
            );
        }

        debug_assert!(
            set.contains("Z3_nz92_koz15EJsos250264"),
            "Set should have contained password, but did not: `Z3_nz92_koz15EJsos250264`"
        );

        assert!(!set.contains("vdK626vxI@E9%NcF%C65"));
        assert!(!set.contains("2AY9L5wl$lfD57UM3tn9"));
        assert!(!set.contains("&Hy!r38&My1V$uJDcX"));
    }
}
