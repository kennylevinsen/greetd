use super::vtselection::VtSelection;

pub fn default_vt() -> VtSelection {
    VtSelection::Next
}

pub fn default_greeter_user() -> String {
    "greeter".to_string()
}
