use super::SignedContent;
use crate::identifier::Identifier;

pub struct Envelope {
    pub id: Vec<u8>,
    pub to: Identifier,
    pub from: Identifier,
    pub message_type: String,
    pub signed_content: SignedContent,
}
