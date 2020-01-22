use std::{
    collections::HashMap,
    error::Error,
    fs,
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
};

use crate::pam::session::PamSession;

fn split_env<'a>(s: &'a str) -> Option<(&'a str, &str)> {
    let components: Vec<&str> = s.splitn(2, '=').collect();
    match components.len() {
        0 => None,
        1 => Some((components[0], "")),
        2 => Some((components[0], components[1])),
        _ => panic!("splitn returned more values than requested"),
    }
}

/// Process environment.d folders to generate the configured environment for
/// the session.
pub fn generate_user_environment(pam: &mut PamSession, home: String) -> Result<(), Box<dyn Error>> {
    let dirs = [
        "/usr/lib/environments.d/",
        "/usr/local/lib/environments.d/",
        "/run/environments.d/",
        "/etc/environments.d/",
        &format!("{}/.config/environment.d", home),
    ];

    let mut env: HashMap<String, String> = HashMap::new();
    for dir in dirs.iter() {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        let mut filepaths: Vec<PathBuf> =
            entries.filter_map(Result::ok).map(|e| e.path()).collect();

        filepaths.sort();

        for filepath in filepaths.into_iter() {
            let reader = BufReader::new(match File::open(&filepath) {
                Ok(f) => f,
                Err(_) => continue,
            });

            for line in reader.lines().filter_map(Result::ok) {
                let (key, value) = match split_env(&line) {
                    Some(v) => v,
                    None => continue,
                };

                if key.starts_with('#') {
                    continue;
                }

                if !value.contains('$') {
                    env.insert(key.to_string(), value.to_string());
                    continue;
                }

                let reference = &value[1..];
                let value = match env.get(reference) {
                    Some(v) => v.to_string(),
                    None => match pam.getenv(reference) {
                        Some(pam_val) => match split_env(pam_val) {
                            Some((_, new_value)) => new_value.to_string(),
                            None => "".to_string(),
                        },
                        None => "".to_string(),
                    },
                };

                env.insert(key.to_string(), value);
            }
        }
    }

    let env = env
        .into_iter()
        .map(|(key, value)| format!("{}={}", key, value));

    for e in env {
        pam.putenv(&e)
            .map_err(|e| format!("unable to set PAM environment: {}", e))?;
    }

    Ok(())
}
