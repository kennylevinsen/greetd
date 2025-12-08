use std::{collections::HashMap, error::Error};

fn parse_field(line: &str) -> Result<(&str, &str), Box<dyn Error>> {
    let Some(split) = line.find('=') else {
        return Err("expected equals sign on line, but found none".into());
    };

    let (key, value) = line.split_at(split);
    let (key, value) = (key.trim(), value.trim_matches('=').trim());

    Ok((key, value))
}

type InishSection<'a> = HashMap<&'a str, &'a str>;
type Inish<'a> = HashMap<&'a str, InishSection<'a>>;

pub fn parse<'a>(s: &'a str) -> Result<Inish<'a>, Box<dyn Error>> {
    let mut sections: Inish<'a> = HashMap::new();
    let mut current_section = HashMap::new();
    let mut current_section_name = "";

    for line in s.lines() {
        let line = line.trim();
        let mut chars = line.chars();
        let start = chars.next();
        let end = chars.last();
        match (start, end) {
            (Some('#'), _) => continue,
            (Some('['), Some(']')) => {
                sections.insert(current_section_name, current_section);
                current_section = HashMap::new();
                let len = line.bytes().count();
                current_section_name = line[1..len - 1].trim();
            }
            (Some('['), v) => {
                return Err(
                    format!("expected Some(']') to terminate section name, but got {v:?}",).into(),
                );
            }
            _ if line.is_empty() => continue,
            _ => {
                let (key, value) = parse_field(line)?;
                current_section.insert(key, value);
            }
        }
    }

    sections.insert(current_section_name, current_section);
    Ok(sections)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sections() {
        let config = parse(
            "
[section_a]
[section_b]
",
        )
        .expect("config didn't parse");

        assert!(config.contains_key("section_a"), "named section should exist");
        assert!(config.contains_key("section_b"), "named section should exist");
        assert!(config.contains_key(""), "unnamed section should exist")
    }

    #[test]
    fn fields() {
        let config = parse(
            "
field_outside = 'hello'
[section_a]
field_a = 1234
",
        )
        .expect("config didn't parse");

        let section_a = match config.get("section_a") {
            Some(v) => v,
            None => panic!("named section did not exist"),
        };

        assert_eq!(section_a.get("field_a"), Some(&"1234"));

        let section_unnamed = match config.get("") {
            Some(v) => v,
            None => panic!("unnamed section did not exist"),
        };

        assert_eq!(section_unnamed.get("field_outside"), Some(&"'hello'"));
    }

    #[test]
    fn whitespaces() {
        let config = parse(
            "

 field outside  =   'hello'

[ section a   ]
   field a   =   1234   ",
        )
        .expect("config didn't parse");

        let section_a = match config.get("section a") {
            Some(v) => v,
            None => panic!("named section did not exist"),
        };

        assert_eq!(section_a.get("field a"), Some(&"1234"));

        let section_unnamed = match config.get("") {
            Some(v) => v,
            None => panic!("unnamed section did not exist"),
        };

        assert_eq!(section_unnamed.get("field outside"), Some(&"'hello'"));
    }
}
