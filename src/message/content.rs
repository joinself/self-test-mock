use crate::error::SelfError;
use crate::keypair::signing::{KeyPair, PublicKey};

use ciborium::value::Value;
use coset::{iana, CborSerializable, CoseSignatureBuilder, Label, ProtectedHeader};

enum HeaderLabel {
    Iat = 100,
    Exp,
}

const SUB: i64 = iana::CwtClaimName::Sub as i64;
const AUD: i64 = iana::CwtClaimName::Aud as i64;
const EXP: i64 = iana::CwtClaimName::Exp as i64;
const IAT: i64 = iana::CwtClaimName::Iat as i64;
const CTI: i64 = iana::CwtClaimName::Cti as i64;
const TYP: i64 = -100000;
const CNT: i64 = -100001;

#[derive(Clone)]
pub struct SignedContent {
    sub: Option<Vec<u8>>,
    aud: Option<Vec<u8>>,
    cti: Option<Vec<u8>>,
    typ: Option<String>,
    iat: Option<i64>,
    exp: Option<i64>,
    content: Option<Vec<u8>>,
    signatures: Vec<Signature>,
}

#[derive(Clone)]
pub struct Signature {
    pub iss: PublicKey,
    pub iat: Option<i64>,
    pub exp: Option<i64>,
    pub protected: Vec<(Label, Value)>,
    pub signature: Vec<u8>,
}

impl SignedContent {
    pub fn new() -> SignedContent {
        SignedContent {
            sub: None,
            aud: None,
            cti: None,
            typ: None,
            iat: None,
            exp: None,
            content: None,
            signatures: Vec::new(),
        }
    }

    pub fn decode(data: &[u8]) -> Result<SignedContent, SelfError> {
        let sm: coset::CoseSign = match coset::CoseSign::from_slice(data) {
            Ok(sm) => sm,
            Err(err) => {
                println!("cbor error: {}", err);
                return Err(SelfError::MessageDecodingInvalid);
            }
        };

        let mut m = SignedContent::new();

        // validate signatures
        for (index, sig) in sm.signatures.iter().enumerate() {
            if sig.protected.is_empty() {
                return Err(SelfError::MessageNoProtected);
            }

            let alg = match sig.protected.header.alg.as_ref() {
                Some(alg) => alg,
                None => return Err(SelfError::MessageUnsupportedSignatureAlgorithm),
            };

            if !alg.eq(&coset::Algorithm::Assigned(coset::iana::Algorithm::EdDSA)) {
                return Err(SelfError::MessageUnsupportedSignatureAlgorithm);
            }

            let signer = PublicKey::from_bytes(
                &sig.protected.header.key_id,
                crate::keypair::Algorithm::Ed25519,
            )?;

            sm.verify_signature(index, &Vec::new(), |sig, data| {
                if signer.verify(data, sig) {
                    return Ok(());
                }
                Err(())
            })
            .map_err(|_| SelfError::MessageSignatureInvalid)?;

            let mut msig = Signature {
                iss: signer,
                iat: None,
                exp: None,
                protected: Vec::new(),
                signature: sig.signature.clone(),
            };

            for (key, value) in &sig.protected.header.rest {
                msig.protected.push((key.to_owned(), value.to_owned()));
            }

            m.signatures.push(msig);
        }

        let encoded_payload = match sm.payload {
            Some(payload) => payload,
            None => return Err(SelfError::MessageNoPayload),
        };

        let payload: Value = ciborium::de::from_reader(&encoded_payload[..])
            .map_err(|_| SelfError::MessagePayloadInvalid)?;

        for entry in payload.as_map().into_iter() {
            if entry.is_empty() {
                continue;
            }

            match &entry[0].0 {
                x if x.eq(&Value::from(AUD)) => {
                    m.aud = Some(
                        entry[0]
                            .1
                            .as_bytes()
                            .ok_or(SelfError::MessageDecodingInvalid)?
                            .clone(),
                    );
                }
                x if x.eq(&Value::from(SUB)) => {
                    m.sub = Some(
                        entry[0]
                            .1
                            .as_bytes()
                            .ok_or(SelfError::MessageDecodingInvalid)?
                            .clone(),
                    );
                }
                x if x.eq(&Value::from(CTI)) => {
                    m.cti = Some(
                        entry[0]
                            .1
                            .as_bytes()
                            .ok_or(SelfError::MessageDecodingInvalid)?
                            .clone(),
                    );
                }
                x if x.eq(&Value::from(TYP)) => {
                    m.typ = Some(
                        entry[0]
                            .1
                            .as_text()
                            .ok_or(SelfError::MessageDecodingInvalid)?
                            .to_string(),
                    );
                }
                x if x.eq(&Value::from(IAT)) => {
                    m.iat = Some(
                        entry[0]
                            .1
                            .as_integer()
                            .ok_or(SelfError::MessageDecodingInvalid)?
                            .try_into()
                            .map_err(|_| SelfError::MessageDecodingInvalid)?,
                    );
                }
                x if x.eq(&Value::from(EXP)) => {
                    m.exp = Some(
                        entry[0]
                            .1
                            .as_integer()
                            .ok_or(SelfError::MessageDecodingInvalid)?
                            .try_into()
                            .map_err(|_| SelfError::MessageDecodingInvalid)?,
                    );
                }
                x if x.eq(&Value::from(CNT)) => {
                    m.content = Some(
                        entry[0]
                            .1
                            .as_bytes()
                            .ok_or(SelfError::MessageDecodingInvalid)?
                            .clone(),
                    );
                }
                _ => {}
            }
        }

        Ok(m)
    }

    pub fn encode(&self) -> Result<Vec<u8>, SelfError> {
        let encoded_payload = self.encode_payload()?;

        let mut sm = coset::CoseSignBuilder::new().payload(encoded_payload);

        for sig in &self.signatures {
            // construct a header for the signer
            let mut header = coset::HeaderBuilder::new()
                .algorithm(iana::Algorithm::EdDSA)
                .key_id(sig.iss.id());

            if let Some(iat) = sig.iat {
                header = header.value(HeaderLabel::Iat as i64, Value::from(iat));
            }

            if let Some(exp) = sig.exp {
                header = header.value(HeaderLabel::Exp as i64, Value::from(exp));
            }

            let signature = CoseSignatureBuilder::new()
                .protected(header.build())
                .signature(sig.signature.clone())
                .build();

            sm = sm.add_signature(signature);
        }

        let signed_message = sm
            .build()
            .to_vec()
            .map_err(|_| SelfError::MessageEncodingInvalid)?;

        Ok(signed_message)
    }

    pub fn sign(&mut self, signer: &KeyPair, exp: Option<i64>) -> Result<(), SelfError> {
        // construct and encode the payload
        let encoded_payload = self.encode_payload()?;

        let iat = crate::time::unix();

        // construct a header for the signer
        let mut header = coset::HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .value(HeaderLabel::Iat as i64, Value::from(iat))
            .key_id(signer.id());

        if let Some(exp) = exp {
            header = header.value(HeaderLabel::Exp as i64, Value::from(exp));
        }

        let message = coset::sig_structure_data(
            coset::SignatureContext::CoseSignature,
            ProtectedHeader {
                original_data: None,
                header: coset::HeaderBuilder::new().build(),
            },
            Some(ProtectedHeader {
                original_data: None,
                header: header.build(),
            }),
            &Vec::new(),
            encoded_payload.as_ref(),
        );

        let signature = signer.sign(&message);

        self.signatures.push(Signature {
            iss: signer.public(),
            iat: Some(iat),
            exp,
            protected: Vec::new(),
            signature,
        });

        Ok(())
    }

    fn encode_payload(&self) -> Result<Vec<u8>, SelfError> {
        // construct and encode the payload
        let mut payload: Vec<(Value, Value)> = Vec::new();
        let mut encoded_payload = Vec::new();

        // map all of the standard fields
        if let Some(aud) = self.aud.as_ref() {
            payload.push((Value::from(AUD), Value::from(aud.clone())));
        }
        if let Some(sub) = self.sub.as_ref() {
            payload.push((Value::from(SUB), Value::from(sub.clone())));
        }
        if let Some(cti) = self.cti.as_ref() {
            payload.push((Value::from(CTI), Value::from(cti.clone())));
        }
        if let Some(typ) = self.typ.as_ref() {
            payload.push((Value::from(TYP), Value::from(typ.clone())));
        }
        if let Some(iat) = self.iat.as_ref() {
            payload.push((Value::from(IAT), Value::from(*iat)));
        }
        if let Some(exp) = self.exp.as_ref() {
            payload.push((Value::from(EXP), Value::from(*exp)));
        }
        if let Some(cnt) = self.content.as_ref() {
            payload.push((Value::from(CNT), Value::from(cnt.clone())));
        }

        ciborium::ser::into_writer(&Value::Map(payload), &mut encoded_payload)
            .map_err(|_| SelfError::MessageEncodingInvalid)?;

        Ok(encoded_payload)
    }

    pub fn audience_set(&mut self, aud: &[u8]) {
        self.aud = Some(aud.to_vec());
    }

    pub fn audience_get(&self) -> Option<Vec<u8>> {
        self.aud.clone()
    }

    pub fn subject_set(&mut self, sub: &[u8]) {
        self.sub = Some(sub.to_vec());
    }

    pub fn subject_get(&self) -> Option<Vec<u8>> {
        self.sub.clone()
    }

    pub fn cti_set(&mut self, cti: &[u8]) {
        self.cti = Some(cti.to_vec());
    }

    pub fn cti_get(&self) -> Option<Vec<u8>> {
        self.cti.clone()
    }

    pub fn type_set(&mut self, typ: &str) {
        self.typ = Some(typ.to_string());
    }

    pub fn type_get(&self) -> Option<String> {
        self.typ.clone()
    }

    pub fn issued_at_set(&mut self, iat: i64) {
        self.iat = Some(iat);
    }

    pub fn issued_at_get(&self) -> Option<i64> {
        self.iat
    }

    pub fn expires_at_set(&mut self, exp: i64) {
        self.exp = Some(exp);
    }

    pub fn expires_at_get(&self) -> Option<i64> {
        self.exp
    }

    pub fn content_set(&mut self, content: &[u8]) {
        self.content = Some(content.to_vec());
    }

    pub fn content_get(&self) -> Option<Vec<u8>> {
        self.content.clone()
    }

    pub fn signatures(&self) -> Vec<Signature> {
        self.signatures.clone()
    }
}

impl Default for SignedContent {
    fn default() -> Self {
        SignedContent::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audience() {
        let mut m = SignedContent::new();

        m.audience_set(&[0; 32]);

        // add a valid signature
        let kp = KeyPair::new();
        m.sign(&kp, None).unwrap();

        // encode to cws
        let cws = m.encode().unwrap();

        // decode from cws
        let m = SignedContent::decode(&cws).unwrap();
        assert!(m.audience_get().unwrap().len() == 32);
    }

    #[test]
    fn subject() {
        let mut m = SignedContent::new();

        m.subject_set(&[0; 32]);

        // add a valid signature
        let kp = KeyPair::new();
        m.sign(&kp, None).unwrap();

        // encode to cws
        let cws = m.encode().unwrap();

        // decode from cws
        let m = SignedContent::decode(&cws).unwrap();
        assert!(m.subject_get().unwrap().len() == 32);
    }

    #[test]
    fn cti() {
        let mut m = SignedContent::new();

        m.cti_set(&[0; 20]);

        // add a valid signature
        let kp = KeyPair::new();
        m.sign(&kp, None).unwrap();

        // encode to cws
        let cws = m.encode().unwrap();

        // decode from cws
        let m = SignedContent::decode(&cws).unwrap();
        assert!(m.cti_get().unwrap().len() == 20);
    }

    #[test]
    fn message_type() {
        let mut m = SignedContent::new();

        m.type_set("connections.req");

        // add a valid signature
        let kp = KeyPair::new();
        m.sign(&kp, None).unwrap();

        // encode to cws
        let cws = m.encode().unwrap();

        // decode from cws
        let m = SignedContent::decode(&cws).unwrap();
        assert_eq!(m.type_get().unwrap(), "connections.req");
    }

    #[test]
    fn issued_at() {
        let mut m = SignedContent::new();

        m.issued_at_set(101);

        // add a valid signature
        let kp = KeyPair::new();
        m.sign(&kp, None).unwrap();

        // encode to cws
        let cws = m.encode().unwrap();

        // decode from cws
        let m = SignedContent::decode(&cws).unwrap();
        assert_eq!(m.issued_at_get().unwrap(), 101);
    }

    #[test]
    fn expires_at() {
        let mut m = SignedContent::new();

        m.expires_at_set(101);

        // add a valid signature
        let kp = KeyPair::new();
        m.sign(&kp, None).unwrap();

        // encode to cws
        let cws = m.encode().unwrap();

        // decode from cws
        let m = SignedContent::decode(&cws).unwrap();

        assert_eq!(m.expires_at_get().unwrap(), 101);
    }

    #[test]
    fn content() {
        let kp = KeyPair::new();
        let mut m = SignedContent::new();

        // add a field to the payload
        let mut content = Vec::new();
        let content_data = vec![(Value::from("my_field"), Value::from(128))];
        ciborium::ser::into_writer(&Value::Map(content_data), &mut content).unwrap();

        // set content and sign
        m.content_set(&content);
        m.sign(&kp, None).unwrap();

        // encode to cws
        let cws = m.encode().unwrap();

        // decode from cws
        let m = SignedContent::decode(&cws).unwrap();

        // decode the content
        let content = m.content_get().unwrap();
        let content_data: Value = ciborium::de::from_reader(&content[..]).unwrap();
        let content_map = content_data.as_map().unwrap();
        assert!(content_map.len() == 1);

        let key = content_map[0].0.as_text().unwrap();
        let value: i64 = content_map[0].1.as_integer().unwrap().try_into().unwrap();
        assert_eq!(key, "my_field");
        assert_eq!(value, 128);
    }
}
