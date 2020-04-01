use std::fmt;

use serde::{
    de::{self, Deserializer, Visitor},
    Deserialize,
};

struct VtSelectionVisitor;

impl<'de> Visitor<'de> for VtSelectionVisitor {
    type Value = VtSelection;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("next, currrent, none or a positive vt number")
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value < 1 {
            Err(de::Error::invalid_value(
                de::Unexpected::Signed(value),
                &"next, current, none or a positive vt number",
            ))
        } else {
            Ok(VtSelection::Specific(value as usize))
        }
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match value {
            "next" => Ok(VtSelection::Next),
            "current" => Ok(VtSelection::Current),
            "none" => Ok(VtSelection::None),
            _ => Err(de::Error::invalid_value(
                de::Unexpected::Str(value),
                &"next, current, none or a postive vt number",
            )),
        }
    }
}

#[derive(Debug)]
pub enum VtSelection {
    Next,
    Current,
    None,
    Specific(usize),
}

impl<'de> Deserialize<'de> for VtSelection {
    fn deserialize<D>(deserializer: D) -> Result<VtSelection, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(VtSelectionVisitor)
    }
}
