use crate::{
    error::SelfError,
    keypair::signing::{KeyPair, PublicKey},
    protocol::siggraph,
};

pub struct OperationBuilder<'a> {
    previous: Option<Vec<u8>>,
    sequence: Option<u32>,
    timestamp: Option<i64>,
    create: Vec<(siggraph::KeyRole, PublicKey)>,
    revoke: Vec<(PublicKey, Option<i64>)>,
    recover: Vec<Option<i64>>,
    operation: Option<Vec<u8>>,
    signatures: Vec<(Vec<u8>, Vec<u8>)>,
    sig_buf: Vec<u8>,
    builder: flatbuffers::FlatBufferBuilder<'a>,
}

impl<'a> OperationBuilder<'a> {
    pub fn new() -> OperationBuilder<'a> {
        return OperationBuilder {
            previous: None,
            sequence: None,
            timestamp: None,
            create: Vec::new(),
            revoke: Vec::new(),
            recover: Vec::new(),
            operation: None,
            signatures: Vec::new(),
            sig_buf: vec![0; 96],
            builder: flatbuffers::FlatBufferBuilder::with_capacity(1024),
        };
    }

    pub fn id(&mut self, id: &[u8]) -> &mut OperationBuilder<'a> {
        self.sig_buf[..32].copy_from_slice(id);
        self
    }

    pub fn sequence(&mut self, sequence: u32) -> &mut OperationBuilder<'a> {
        self.sequence = Some(sequence);
        self
    }

    pub fn timestamp(&mut self, timestamp: i64) -> &mut OperationBuilder<'a> {
        self.timestamp = Some(timestamp);
        self
    }

    pub fn previous(&mut self, hash: &[u8]) -> &mut OperationBuilder<'a> {
        self.previous = Some(hash.to_vec());
        self
    }

    pub fn key_create_signing(&mut self, pk: &PublicKey) -> &mut OperationBuilder<'a> {
        self.create
            .push((siggraph::KeyRole::Signing, pk.to_owned()));
        self
    }

    pub fn key_create_recovery(&mut self, pk: &PublicKey) -> &mut OperationBuilder<'a> {
        self.create
            .push((siggraph::KeyRole::Recovery, pk.to_owned()));
        self
    }

    pub fn key_revoke(
        &mut self,
        pk: &PublicKey,
        effective_from: Option<i64>,
    ) -> &mut OperationBuilder<'a> {
        self.revoke.push((pk.to_owned(), effective_from));
        self
    }

    pub fn recovery(&mut self, effective_from: Option<i64>) -> &mut OperationBuilder<'a> {
        self.recover.push(effective_from);
        self
    }

    pub fn sign(&mut self, kp: &KeyPair) -> &mut OperationBuilder<'a> {
        if self.operation.is_none() {
            self.build_operation();
        }

        self.builder.reset();

        let sb = self.builder.create_vector(&kp.id());

        let header = siggraph::SignatureHeader::create(
            &mut self.builder,
            &siggraph::SignatureHeaderArgs { signer: Some(sb) },
        );

        self.builder.finish(header, None);

        let header_bytes = self.builder.finished_data().to_vec();
        let header_hash = crate::crypto::hash::blake2b(&header_bytes);
        self.builder.reset();

        self.sig_buf[64..].copy_from_slice(&header_hash);
        let signature = kp.sign(&self.sig_buf);

        self.signatures.push((header_bytes, signature));

        self
    }

    pub fn build(&mut self) -> Result<Vec<u8>, SelfError> {
        if self.operation.is_none() {
            return Err(SelfError::SiggraphOperationDecodingInvalid);
        }

        if self.signatures.is_empty() {
            return Err(SelfError::SiggraphOperationNotEnoughSigners);
        }

        let mut signatures = Vec::new();

        for signature in &self.signatures {
            let hb = self.builder.create_vector(&signature.0);
            let sb = self.builder.create_vector(&signature.1);

            signatures.push(siggraph::Signature::create(
                &mut self.builder,
                &siggraph::SignatureArgs {
                    header: Some(hb),
                    signature: Some(sb),
                },
            ));
        }

        let op_signatures = self.builder.create_vector(&signatures);
        let op_data = self.builder.create_vector(self.operation.as_ref().unwrap());

        let signed_op = siggraph::SignedOperation::create(
            &mut self.builder,
            &siggraph::SignedOperationArgs {
                operation: Some(op_data),
                signatures: Some(op_signatures),
            },
        );

        self.builder.finish(signed_op, None);

        let signed_op_bytes = self.builder.finished_data().to_vec();

        Ok(signed_op_bytes)
    }

    fn build_operation(&mut self) {
        // TODO gracefully return error when optioned values are None
        let mut actions = Vec::new();

        for recover in &self.recover {
            let effective_from = recover.unwrap_or(self.timestamp.unwrap());

            let rk = siggraph::Recover::create(
                &mut self.builder,
                &siggraph::RecoverArgs { effective_from },
            );

            let ac = siggraph::Action::create(
                &mut self.builder,
                &siggraph::ActionArgs {
                    actionable_type: siggraph::Actionable::Recover,
                    actionable: Some(rk.as_union_value()),
                },
            );

            actions.push(ac);
        }

        for revoke in &self.revoke {
            let effective_from = revoke.1.unwrap_or_else(|| self.timestamp.unwrap());

            let kb = self.builder.create_vector(&revoke.0.id());

            let rk = siggraph::RevokeKey::create(
                &mut self.builder,
                &siggraph::RevokeKeyArgs {
                    key: Some(kb),
                    effective_from,
                },
            );

            let ac = siggraph::Action::create(
                &mut self.builder,
                &siggraph::ActionArgs {
                    actionable_type: siggraph::Actionable::RevokeKey,
                    actionable: Some(rk.as_union_value()),
                },
            );

            actions.push(ac);
        }

        for create in &self.create {
            let kb = self.builder.create_vector(&create.1.id());

            let ck = siggraph::CreateKey::create(
                &mut self.builder,
                &siggraph::CreateKeyArgs {
                    key: Some(kb),
                    alg: siggraph::KeyAlgorithm::Ed25519,
                    role: create.0,
                    effective_from: self.timestamp.unwrap(),
                },
            );

            let ac = siggraph::Action::create(
                &mut self.builder,
                &siggraph::ActionArgs {
                    actionable_type: siggraph::Actionable::CreateKey,
                    actionable: Some(ck.as_union_value()),
                },
            );

            actions.push(ac);
        }

        let actions_vec = self.builder.create_vector(&actions);
        let previous = self
            .previous
            .as_ref()
            .map(|hash| self.builder.create_vector(hash));

        let op = siggraph::Operation::create(
            &mut self.builder,
            &siggraph::OperationArgs {
                version: 2,
                sequence: self.sequence.unwrap(),
                timestamp: self.timestamp.unwrap(),
                previous,
                actions: Some(actions_vec),
            },
        );

        self.builder.finish(op, None);

        // calculate hash over operation for signatures
        let op_bytes = self.builder.finished_data().to_vec();
        let op_hash = crate::crypto::hash::blake2b(&op_bytes);
        self.builder.reset();

        // copy the operation hash to the signature buffer
        self.sig_buf[32..64].copy_from_slice(&op_hash);

        self.operation = Some(op_bytes);
    }
}

impl Default for OperationBuilder<'_> {
    fn default() -> Self {
        OperationBuilder::new()
    }
}
