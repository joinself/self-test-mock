use crate::identifier::Identifier;
use crate::message::SignedContent;
use crate::models::Authentication;
use crate::{error::SelfError, keypair::signing::PublicKey};

use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{TimeZone, Utc};

pub fn validate(token: &[u8]) -> Result<Vec<Identifier>, SelfError> {
    let sm = SignedContent::decode(token)?;

    if sm.type_get().expect("failed to get types") != "authentication" {
        return Err(SelfError::MessageNoPayload);
    }

    let mut authorized: Vec<Identifier> = sm
        .signatures()
        .into_iter()
        .map(|s| Identifier::Referenced(s.iss.id()))
        .collect();

    if let Some(content) = sm.content_get() {
        let content: Authentication = ciborium::de::from_reader(&content as &[u8])
            .map_err(|_| SelfError::MessageNoPayload)?;

        // | messagingv3.SignatureType | promiscuous (0) or targeted (1) | nonce 20 bytes | unix timestamp seconds expiry | identity 32 bytes |signature 64 bytes |
        let exp = match (&content.tkn[22..30] as &[u8]).read_i64::<LittleEndian>() {
            Ok(exp) => Utc.timestamp_opt(exp, 0).unwrap(),
            Err(_) => return Err(SelfError::MessageNoPayload),
        };

        if Utc::now() > exp {
            // the token has expired!
            return Err(SelfError::MessageNoPayload);
        }

        match token[1] {
            1 => {
                if Identifier::Referenced(Vec::from((&token[30..62]) as &[u8])) != authorized[0] {
                    // the token was issued for another identifier
                    return Err(SelfError::MessageNoPayload);
                }
            }
            _ => return Err(SelfError::MessageNoPayload),
        }

        let pk = PublicKey::from_bytes(&content.iss, crate::keypair::Algorithm::Ed25519)?;

        if !pk.verify(&token[..token.len() - 64], &token[token.len() - 64..]) {
            return Err(SelfError::MessageSignatureEncodingInvalid);
        }

        authorized.push(Identifier::Referenced(content.iss));
    }

    Ok(authorized)
}
