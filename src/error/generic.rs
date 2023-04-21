use std::error::Error;
use std::fmt;
#[derive(Debug)]
pub struct GenericError {
    pub details: String,
}

impl GenericError {
    pub fn new(msg: &str) -> GenericError {
        GenericError {
            details: msg.to_string(),
        }
    }
}

impl fmt::Display for GenericError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl Error for GenericError {
    fn description(&self) -> &str {
        &self.details
    }
}
