use flatbuffers::{ForwardsUOffset, Vector};

use crate::error::SelfError;
use crate::keypair::signing::PublicKey;
use crate::keypair::Algorithm;
use crate::protocol::siggraph::{
    root_as_signed_operation, Action, Actionable, CreateKey, KeyAlgorithm, KeyRole, Operation,
    Recover, RevokeKey, Signature, SignatureHeader, SignedOperation,
};
use crate::siggraph::{node::Node, operation::OperationBuilder};

use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

pub struct SignatureGraph {
    id: Option<Vec<u8>>,
    root: Option<Rc<RefCell<Node>>>,
    keys: HashMap<Vec<u8>, Rc<RefCell<Node>>>,
    hashes: HashMap<Vec<u8>, usize>,
    operations: Vec<Vec<u8>>,
    recovery_key: Option<Rc<RefCell<Node>>>,
    sig_buf: Vec<u8>,
}

impl SignatureGraph {
    pub fn new() -> SignatureGraph {
        SignatureGraph {
            id: None,
            root: None,
            keys: HashMap::new(),
            hashes: HashMap::new(),
            operations: Vec::new(),
            recovery_key: None,
            sig_buf: vec![0; 96],
        }
    }

    pub fn load(history: &[Vec<u8>], verify: bool) -> Result<SignatureGraph, SelfError> {
        let mut sg = SignatureGraph {
            id: None,
            root: None,
            keys: HashMap::new(),
            hashes: HashMap::new(),
            operations: Vec::new(),
            recovery_key: None,
            sig_buf: vec![0; 96],
        };

        for operation in history {
            sg.execute_operation(operation.to_owned(), verify)?
        }

        Ok(sg)
    }

    pub fn create(&self) -> OperationBuilder {
        let mut ob = OperationBuilder::new();

        ob.sequence(self.operations.len() as u32)
            .timestamp(crate::time::unix());

        if let Some(id) = &self.id {
            ob.id(id);
        }

        if let Some(last_op) = self.operations.last() {
            // compute the hash of the last operation
            ob.previous(&crate::crypto::hash::blake2b(last_op));
        }

        ob
    }

    pub fn execute(&mut self, operation: Vec<u8>) -> Result<(), SelfError> {
        self.execute_operation(operation, true)
    }

    fn execute_operation(&mut self, operation: Vec<u8>, verify: bool) -> Result<(), SelfError> {
        let signed_op = root_as_signed_operation(&operation)
            .map_err(|_| SelfError::SiggraphOperationDecodingInvalid)?;

        let signed_op_hash = crate::crypto::hash::blake2b(&operation);

        let op_bytes = signed_op
            .operation()
            .ok_or(SelfError::SiggraphOperationDecodingInvalid)?;

        let op = flatbuffers::root::<Operation>(op_bytes)
            .map_err(|_| SelfError::SiggraphOperationDecodingInvalid)?;

        let mut signers = HashSet::new();

        if verify {
            let op_hash = crate::crypto::hash::blake2b(op_bytes);
            // copy the operation hash to our temporary buffer we
            // will use to calculate signatures for each signer
            self.sig_buf[32..64].copy_from_slice(&op_hash);

            self.validate_operation(&signed_op, &op, &mut signers)?;
            self.authorize_operation(&op, &signers)?;
        }

        let actions = match op.actions() {
            Some(actions) => actions,
            None => return Err(SelfError::SiggraphOperationNOOP),
        };

        if verify {
            self.validate_actions(&op, &actions, &signers)?;
        }

        self.execute_actions(&op, &actions, &signers)?;

        self.hashes.insert(signed_op_hash, self.operations.len());
        self.operations.push(operation);

        Ok(())
    }

    fn validate_operation(
        &mut self,
        signed_op: &SignedOperation,
        op: &Operation,
        signers: &mut HashSet<Vec<u8>>,
    ) -> Result<(), SelfError> {
        // check the sequence is in order and version of the operation are correct
        if op.sequence() != self.operations.len() as u32 {
            return Err(SelfError::SiggraphOperationSequenceOutOfOrder);
        }

        if op.version() != 2 {
            return Err(SelfError::SiggraphOperationVersionInvalid);
        }

        if op.actions().is_none() {
            return Err(SelfError::SiggraphOperationNOOP);
        }
        // TODO replace with is_some_and once stable
        if let Some(actions) = op.actions() {
            if actions.is_empty() {
                return Err(SelfError::SiggraphOperationNOOP);
            }
        }

        let signatures = match signed_op.signatures() {
            Some(signatures) => signatures,
            None => return Err(SelfError::SiggraphOperationNotSigned),
        };

        if op.sequence() == 0 {
            // check the root operation contains a signature using the secret key
            // used to generate the identifier for the account, as well as a signature
            // by the device and recovery key
            if signatures.len() < 3 {
                return Err(SelfError::SiggraphOperationNotEnoughSigners);
            }
        } else {
            let previous = match op.previous() {
                Some(previous) => previous,
                None => return Err(SelfError::SiggraphOperationPreviousHashMissing),
            };

            let hash_index = match self.hashes.get(previous) {
                Some(hash_index) => *hash_index,
                None => return Err(SelfError::SiggraphOperationPreviousHashInvalid),
            };

            // check the provided previous hash matches the hash of the last operation
            if hash_index != self.operations.len() - 1 {
                return Err(SelfError::SiggraphOperationPreviousHashInvalid);
            }

            // check the timestamp is greater than the previous operations
            if self.operation(self.operations.len() - 1).timestamp() == op.timestamp()
                || self.operation(self.operations.len() - 1).timestamp() > op.timestamp()
            {
                return Err(SelfError::SiggraphOperationTimestampInvalid);
            }
        }

        for (i, sig) in signatures.iter().enumerate() {
            let hdr_bytes = match sig.header() {
                Some(hdr_bytes) => hdr_bytes,
                None => return Err(SelfError::SiggraphOperationSignatureHeaderMissing),
            };

            let signature = match sig.signature() {
                Some(signature) => signature,
                None => return Err(SelfError::SiggraphOperationSignatureInvalid),
            };

            let hdr_hash = crate::crypto::hash::blake2b(hdr_bytes);
            self.sig_buf[64..].copy_from_slice(&hdr_hash);

            let hdr = flatbuffers::root::<SignatureHeader<'_>>(hdr_bytes)
                .map_err(|_| SelfError::SiggraphOperationSignatureHeaderInvalid)?;

            let signer = match hdr.signer() {
                Some(signer) => signer,
                None => return Err(SelfError::SiggraphOperationSignatureSignerMissing),
            };

            if op.sequence() == 0 && i == 0 {
                // if this is the first signature on the first operation
                // this is the key used as an identifier for the account.
                // copy it to the sig buffer for verifying signatures
                self.id = Some(signer.to_vec());
                self.sig_buf[..32].copy_from_slice(signer);
            }

            // TODO store signature alg in header
            let signers_pk = PublicKey::from_bytes(signer, crate::keypair::Algorithm::Ed25519)?;
            if !signers_pk.verify(&self.sig_buf, signature) {
                return Err(SelfError::SiggraphOperationSignatureInvalid);
            };

            signers.insert(signer.to_vec());
        }

        Ok(())
    }

    fn authorize_operation(
        &self,
        op: &Operation,
        signers: &HashSet<Vec<u8>>,
    ) -> Result<(), SelfError> {
        if op.sequence() < 1 {
            return Ok(());
        }

        let mut authorized = false;

        for signer in signers {
            let signing_key = match self.keys.get(signer) {
                Some(signing_key) => signing_key,
                None => continue,
            };

            let created_at = (*signing_key).as_ref().borrow().ca;
            let revoked_at = (*signing_key).as_ref().borrow().ra;

            if op.timestamp() < created_at {
                return Err(SelfError::SiggraphOperationSignatureKeyRevoked);
            }

            // check the signign key hasn't been revoked before the operation
            if revoked_at > 0 && op.timestamp() > revoked_at {
                return Err(SelfError::SiggraphOperationSignatureKeyRevoked);
            }

            authorized = true;
        }

        if !authorized {
            return Err(SelfError::SiggraphOperationSigningKeyInvalid);
        }

        Ok(())
    }

    fn validate_actions(
        &self,
        op: &Operation,
        actions: &Vector<ForwardsUOffset<Action>>,
        signers: &HashSet<Vec<u8>>,
    ) -> Result<(), SelfError> {
        let mut active_keys = HashMap::new();

        self.keys.iter().for_each(|(key, value)| {
            if value.as_ref().borrow().ra == 0 {
                let typ = value.as_ref().borrow().typ;
                active_keys.insert(key.clone(), typ);
            }
        });

        for action in actions {
            match action.actionable_type() {
                Actionable::CreateKey => {
                    let create_key = action.actionable_as_create_key().unwrap();
                    self.validate_create_key(op, &create_key, signers, &mut active_keys)?;
                }
                Actionable::RevokeKey => {
                    let revoke_key = action.actionable_as_revoke_key().unwrap();
                    self.validate_revoke_key(op, &revoke_key, &mut active_keys)?;
                }
                Actionable::Recover => {
                    let recover = action.actionable_as_recover().unwrap();
                    self.validate_recover(op, &recover, signers, &mut active_keys)?;
                }
                _ => return Err(SelfError::SiggraphActionUnknown),
            }
        }

        if active_keys.is_empty() {
            return Err(SelfError::SiggraphOperationNoValidKeys);
        }

        let mut signing_keys = 0;
        let mut recovery_keys = 0;

        for role in active_keys.values() {
            if *role == KeyRole::Signing {
                signing_keys += 1;
            } else if *role == KeyRole::Recovery {
                recovery_keys += 1;
            }
        }

        if signing_keys < 1 {
            return Err(SelfError::SiggraphOperationNoValidKeys);
        }

        if recovery_keys < 1 {
            return Err(SelfError::SiggraphOperationNoValidRecoveryKey);
        }

        if recovery_keys > 1 {
            return Err(SelfError::SiggraphActionMultipleActiveRecoveryKeys);
        }

        Ok(())
    }

    fn execute_actions(
        &mut self,
        op: &Operation,
        actions: &Vector<ForwardsUOffset<Action>>,
        signers: &HashSet<Vec<u8>>,
    ) -> Result<(), SelfError> {
        // TODO pre-validate actions before executing any changes to the graphs state
        for action in actions {
            match action.actionable_type() {
                Actionable::CreateKey => {
                    let create_key = action.actionable_as_create_key().unwrap();
                    self.execute_create_key(op, &create_key, signers)?;
                }
                Actionable::RevokeKey => {
                    let revoke_key = action.actionable_as_revoke_key().unwrap();
                    self.execute_revoke_key(&revoke_key)?;
                }
                Actionable::Recover => {
                    let recover = action.actionable_as_recover().unwrap();
                    self.execute_recover(&recover)?;
                }
                _ => return Err(SelfError::SiggraphActionUnknown),
            }
        }

        Ok(())
    }

    fn validate_create_key(
        &self,
        op: &Operation,
        ck: &CreateKey,
        signers: &HashSet<Vec<u8>>,
        active_keys: &mut HashMap<Vec<u8>, KeyRole>,
    ) -> Result<(), SelfError> {
        let key = match ck.key() {
            Some(key) => key,
            None => return Err(SelfError::SiggraphActionKeyMissing),
        };

        // check this key is not the key used to as the identities identifier
        if let Some(id) = self.id.as_ref() {
            if id.eq(key) {
                return Err(SelfError::SiggraphActionKeyDuplicate);
            }
        }

        if !signers.contains(key) {
            return Err(SelfError::SiggraphOperationNotEnoughSigners);
        }

        if active_keys.contains_key(key) {
            return Err(SelfError::SiggraphActionKeyDuplicate);
        }

        if op.sequence() > 0 && ck.effective_from() < self.operation(0).timestamp() {
            return Err(SelfError::SiggraphOperationTimestampInvalid);
        }

        if ck.role() == KeyRole::Recovery {
            // TODO replace with is_some_and when stable
            if let Some(recovery_key) = self.recovery_key.as_ref() {
                if recovery_key.as_ref().borrow().ra == 0 {
                    return Err(SelfError::SiggraphActionMultipleActiveRecoveryKeys);
                }
            }
        }

        active_keys.insert(key.to_vec(), ck.role());

        Ok(())
    }

    fn execute_create_key(
        &mut self,
        op: &Operation,
        ck: &CreateKey,
        signers: &HashSet<Vec<u8>>,
    ) -> Result<(), SelfError> {
        let key = match ck.key() {
            Some(key) => key,
            None => return Err(SelfError::SiggraphActionKeyMissing),
        };

        let node = Rc::new(RefCell::new(Node {
            typ: ck.role(),
            seq: op.sequence(),
            ca: op.timestamp(),
            ra: 0,
            pk: PublicKey::from_bytes(key, Algorithm::Ed25519)?,
            incoming: Vec::new(),
            outgoing: Vec::new(),
        }));

        self.keys.insert(key.to_vec(), node.clone());

        for signer in signers {
            if op.sequence() == 0 && self.root.is_none() {
                if key.eq(signer) {
                    // TODO replace with is_some_and once stable
                    if let Some(id) = self.id.as_ref() {
                        if !key.eq(id) {
                            self.root = Some(node.clone());
                        }
                    }
                }
                continue;
            }

            if key.eq(signer) {
                // this is a self signed signature, skip it
                continue;
            }

            let parent = match self.keys.get(signer) {
                Some(parent) => parent,
                None => continue,
            };

            node.as_ref().borrow_mut().incoming.push((*parent).clone());
            parent.as_ref().borrow_mut().outgoing.push(node.clone());
        }

        Ok(())
    }

    fn validate_revoke_key(
        &self,
        op: &Operation,
        rk: &RevokeKey,
        active_keys: &mut HashMap<Vec<u8>, KeyRole>,
    ) -> Result<(), SelfError> {
        let key = match rk.key() {
            Some(key) => key,
            None => return Err(SelfError::SiggraphActionKeyMissing),
        };

        let node = match self.keys.get(key) {
            Some(node) => node,
            None => return Err(SelfError::SiggraphActionKeyMissing),
        };

        // if this is the first (root) operation, then key revocation is not permitted
        if op.sequence() == 0 {
            return Err(SelfError::SiggraphActionInvalidKeyRevocation);
        }

        // check that the revoke action does not take effect before the first
        // operations timestamp
        if rk.effective_from() < self.operation(0).timestamp() {
            return Err(SelfError::SiggraphOperationTimestampInvalid);
        }

        // if the key has been revoked, then fail
        if node.as_ref().borrow().ra != 0 {
            return Err(SelfError::SiggraphActionKeyAlreadyRevoked);
        }

        // check if the effective from timestamp is after the first operation
        if rk.effective_from() < self.operation(0).timestamp() {
            return Err(SelfError::SiggraphOperationTimestampInvalid);
        }

        active_keys.remove(key);

        Ok(())
    }

    fn execute_revoke_key(&mut self, rk: &RevokeKey) -> Result<(), SelfError> {
        let key = match rk.key() {
            Some(key) => key,
            None => return Err(SelfError::SiggraphActionKeyMissing),
        };

        let node = match self.keys.get(key) {
            Some(node) => node,
            None => return Err(SelfError::SiggraphActionKeyMissing),
        };

        node.borrow_mut().ra = rk.effective_from();

        // get and re-borrow revoked key as immutable ref this time
        let node = self
            .keys
            .get(key)
            .ok_or(SelfError::SiggraphActionSigningKeyInvalid)?
            .clone();

        let revoked_key = node.as_ref().borrow();

        // revoke all child keys created after the revocation takes effect
        for child_node in revoked_key.collect() {
            let mut child_key = child_node.as_ref().borrow_mut();

            if child_key.ca >= rk.effective_from() {
                child_key.ra = rk.effective_from();
            }
        }

        Ok(())
    }

    fn validate_recover(
        &self,
        op: &Operation,
        rc: &Recover,
        signers: &HashSet<Vec<u8>>,
        active_keys: &mut HashMap<Vec<u8>, KeyRole>,
    ) -> Result<(), SelfError> {
        // if this is the first (root) operation, then recovery is not permitted
        if op.sequence() == 0 {
            return Err(SelfError::SiggraphActionInvalidKeyRevocation);
        }

        // check that the recovery action does not take effect before the first
        // operations timestamp
        if rc.effective_from() < self.operation(0).timestamp() {
            return Err(SelfError::SiggraphOperationTimestampInvalid);
        }

        // check this operation has been signed by the existing recovery key
        if let Some(recovery_key) = self.recovery_key.as_ref() {
            if !signers.contains(&recovery_key.as_ref().borrow().pk.id()) {
                return Err(SelfError::SiggraphOperationAccountRecoveryActionInvalid);
            }
        }

        let root = self.root.as_ref().unwrap().as_ref().borrow();

        // revoke all of the current active keys
        for child_node in root.collect() {
            let key = child_node.as_ref().borrow().pk.id();
            active_keys.remove(&key);
        }

        Ok(())
    }

    fn execute_recover(&mut self, rc: &Recover) -> Result<(), SelfError> {
        // if the signing key was a recovery key, then nuke all existing keys
        let mut root = self.root.as_ref().unwrap().as_ref().borrow_mut();
        root.ra = rc.effective_from();

        for child_node in root.collect() {
            let mut child_key = child_node.as_ref().borrow_mut();
            if child_key.ra == 0 {
                child_key.ra = rc.effective_from();
            }
        }

        Ok(())
    }

    pub fn is_key_valid(&self, id: &[u8], at: i64) -> bool {
        let k = match self.keys.get(id) {
            Some(k) => k.as_ref(),
            None => return false,
        }
        .borrow();

        if k.ca == 0 {
            return false;
        }

        if !(k.ra != 0 || k.ca != at && k.ca >= at) {
            return true;
        }

        if k.ra == 0 {
            return false;
        }

        if !(k.ra <= at || k.ca != at && k.ca >= at) {
            return true;
        }

        false
    }

    fn operation(&self, index: usize) -> Operation {
        let signed_op = root_as_signed_operation(&self.operations[index]).unwrap();

        let op_bytes = signed_op.operation().unwrap();

        return flatbuffers::root::<Operation>(op_bytes).unwrap();
    }
}

impl Default for SignatureGraph {
    fn default() -> Self {
        SignatureGraph::new()
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use flatbuffers::{Vector, WIPOffset};

    use crate::{
        error::SelfError,
        keypair::signing::KeyPair,
        protocol::siggraph::{
            Action, ActionArgs, Actionable, CreateKey, CreateKeyArgs, KeyAlgorithm, KeyRole,
            Operation, OperationArgs, Recover, RecoverArgs, RevokeKey, RevokeKeyArgs, Signature,
            SignatureArgs, SignatureHeader, SignatureHeaderArgs, SignedOperation,
            SignedOperationArgs,
        },
        siggraph::SignatureGraph,
    };

    struct TestSigner {
        id: Vec<u8>,
        sk: KeyPair,
    }

    struct TestAction {
        key: Vec<u8>,
        alg: KeyAlgorithm,
        role: KeyRole,
        actionable: Actionable,
        effective_from: i64,
    }

    struct TestOperation {
        id: KeyPair,
        version: u8,
        sequence: u32,
        timestamp: i64,
        previous: Vec<u8>,
        actions: Vec<TestAction>,
        signers: Vec<TestSigner>,
        error: Result<(), SelfError>,
    }

    fn test_keys() -> Vec<KeyPair> {
        let mut keys = Vec::new();

        for _ in 0..10 {
            let kp = KeyPair::new();
            keys.push(kp);
        }

        keys
    }

    fn test_operation(test_op: &mut TestOperation) -> (Vec<u8>, Vec<u8>) {
        let mut op_builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);
        let mut sg_builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);
        let mut fn_builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);

        let mut actions = Vec::new();

        for action in &test_op.actions {
            match action.actionable {
                Actionable::CreateKey => {
                    let kb = op_builder.create_vector(&action.key);

                    let ck = CreateKey::create(
                        &mut op_builder,
                        &CreateKeyArgs {
                            key: Some(kb),
                            alg: action.alg,
                            role: action.role,
                            effective_from: action.effective_from,
                        },
                    );

                    let ac = Action::create(
                        &mut op_builder,
                        &ActionArgs {
                            actionable_type: Actionable::CreateKey,
                            actionable: Some(ck.as_union_value()),
                        },
                    );

                    actions.push(ac);
                }
                Actionable::RevokeKey => {
                    let kb = op_builder.create_vector(&action.key);

                    let rk = RevokeKey::create(
                        &mut op_builder,
                        &RevokeKeyArgs {
                            key: Some(kb),
                            effective_from: action.effective_from,
                        },
                    );

                    let ac = Action::create(
                        &mut op_builder,
                        &ActionArgs {
                            actionable_type: Actionable::RevokeKey,
                            actionable: Some(rk.as_union_value()),
                        },
                    );

                    actions.push(ac);
                }
                Actionable::Recover => {
                    let rk = Recover::create(
                        &mut op_builder,
                        &RecoverArgs {
                            effective_from: action.effective_from,
                        },
                    );

                    let ac = Action::create(
                        &mut op_builder,
                        &ActionArgs {
                            actionable_type: Actionable::Recover,
                            actionable: Some(rk.as_union_value()),
                        },
                    );

                    actions.push(ac);
                }
                _ => {}
            }
        }

        let actions_vec = op_builder.create_vector(&actions);
        let mut previous: Option<WIPOffset<Vector<u8>>> = None;

        if !test_op.previous.is_empty() {
            previous = Some(op_builder.create_vector(&test_op.previous));
        }

        let op = Operation::create(
            &mut op_builder,
            &OperationArgs {
                version: test_op.version,
                sequence: test_op.sequence,
                timestamp: test_op.timestamp,
                previous,
                actions: Some(actions_vec),
            },
        );

        op_builder.finish(op, None);

        let op_hash = crate::crypto::hash::blake2b(op_builder.finished_data());

        let mut sig_buf: Vec<u8> = vec![0; 96];
        sig_buf[..32].copy_from_slice(&test_op.id.id());
        sig_buf[32..64].copy_from_slice(&op_hash);

        let mut signatures = Vec::new();

        for signer in &test_op.signers {
            sg_builder.reset();

            let sb = sg_builder.create_vector(&signer.id);

            let header =
                SignatureHeader::create(&mut sg_builder, &SignatureHeaderArgs { signer: Some(sb) });

            sg_builder.finish(header, None);

            let header_hash = crate::crypto::hash::blake2b(sg_builder.finished_data());

            sig_buf[64..].copy_from_slice(&header_hash);
            let signature = signer.sk.sign(&sig_buf);

            let hb = fn_builder.create_vector(sg_builder.finished_data());
            let sb = fn_builder.create_vector(&signature);

            let sig = Signature::create(
                &mut fn_builder,
                &SignatureArgs {
                    header: Some(hb),
                    signature: Some(sb),
                },
            );

            signatures.push(sig);
        }

        let op_signatures = fn_builder.create_vector(&signatures);
        let op_data = fn_builder.create_vector(op_builder.finished_data());

        let signed_op = SignedOperation::create(
            &mut fn_builder,
            &SignedOperationArgs {
                operation: Some(op_data),
                signatures: Some(op_signatures),
            },
        );

        fn_builder.finish(signed_op, None);

        let signed_op_hash = crate::crypto::hash::blake2b(fn_builder.finished_data());

        return (fn_builder.finished_data().to_vec(), signed_op_hash);
    }

    fn test_execute(test_history: &mut Vec<TestOperation>) -> SignatureGraph {
        let mut sg = SignatureGraph::new();
        let mut previous_hash: Option<Vec<u8>> = None;

        for mut test_op in test_history {
            if test_op.previous.is_empty() {
                if let Some(previous) = previous_hash {
                    test_op.previous = previous;
                }
            }

            let (signed_op, previous) = test_operation(test_op);

            previous_hash = Some(previous);

            let result = sg.execute(signed_op);
            if test_op.error.is_err() {
                assert_eq!(
                    result.err().unwrap(),
                    *test_op.error.as_ref().err().unwrap()
                );
            } else {
                if result.is_err() {
                    println!("{:?}", result);
                }
                assert_eq!(test_op.error.is_ok(), result.is_ok());
            }
        }

        sg
    }

    #[test]
    fn execute_valid_single_entry() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![TestOperation {
            id: keys[0].clone(),
            version: 2,
            sequence: 0,
            timestamp: now,
            previous: Vec::new(),
            signers: vec![
                TestSigner {
                    id: keys[0].id(),
                    sk: keys[0].clone(),
                },
                TestSigner {
                    id: keys[1].id(),
                    sk: keys[1].clone(),
                },
                TestSigner {
                    id: keys[2].id(),
                    sk: keys[2].clone(),
                },
            ],
            actions: vec![
                TestAction {
                    key: keys[1].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: 0,
                },
                TestAction {
                    key: keys[2].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Recovery,
                    actionable: Actionable::CreateKey,
                    effective_from: 0,
                },
            ],
            error: Ok(()),
        }];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_valid_multi_entry() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 1,
                }],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 2,
                timestamp: now + 2,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[4].id(),
                        sk: keys[4].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[4].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 2,
                }],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 3,
                timestamp: now + 3,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                    TestSigner {
                        id: keys[5].id(),
                        sk: keys[5].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[5].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 3,
                }],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 4,
                timestamp: now + 4,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[4].id(),
                        sk: keys[4].clone(),
                    },
                    TestSigner {
                        id: keys[6].id(),
                        sk: keys[6].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[6].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 4,
                }],
                error: Ok(()),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_valid_multi_entry_with_recovery() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 1,
                }],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 2,
                timestamp: now + 2,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[4].id(),
                        sk: keys[4].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[4].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 2,
                }],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 3,
                timestamp: now + 3,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                    TestSigner {
                        id: keys[5].id(),
                        sk: keys[5].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[5].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 3,
                }],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 4,
                timestamp: now + 4,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[4].id(),
                        sk: keys[4].clone(),
                    },
                    TestSigner {
                        id: keys[6].id(),
                        sk: keys[6].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[6].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 4,
                }],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 5,
                timestamp: now + 5,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                    TestSigner {
                        id: keys[7].id(),
                        sk: keys[7].clone(),
                    },
                    TestSigner {
                        id: keys[8].id(),
                        sk: keys[8].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::Recover,
                        effective_from: now + 5,
                    },
                    TestAction {
                        key: keys[7].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now + 5,
                    },
                    TestAction {
                        key: keys[8].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now + 5,
                    },
                ],
                error: Ok(()),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_sequence_ordering() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 3,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 1,
                }],
                error: Err(SelfError::SiggraphOperationSequenceOutOfOrder),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_timestamp() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now,
                }],
                error: Err(SelfError::SiggraphOperationTimestampInvalid),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_previous_hash() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: vec![0; 32],
                signers: vec![
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 1,
                }],
                error: Err(SelfError::SiggraphOperationPreviousHashInvalid),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_signature() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[4].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 1,
                }],
                error: Err(SelfError::SiggraphOperationSignatureInvalid),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_signature_identity() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![TestOperation {
            id: keys[0].clone(),
            version: 2,
            sequence: 0,
            timestamp: now,
            previous: Vec::new(),
            signers: vec![
                TestSigner {
                    id: keys[0].id(),
                    sk: keys[4].clone(),
                },
                TestSigner {
                    id: keys[1].id(),
                    sk: keys[1].clone(),
                },
                TestSigner {
                    id: keys[2].id(),
                    sk: keys[2].clone(),
                },
            ],
            actions: vec![
                TestAction {
                    key: keys[1].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now,
                },
                TestAction {
                    key: keys[2].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Recovery,
                    actionable: Actionable::CreateKey,
                    effective_from: now,
                },
            ],
            error: Err(SelfError::SiggraphOperationSignatureInvalid),
        }];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_signature_key() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![TestOperation {
            id: keys[0].clone(),
            version: 2,
            sequence: 0,
            timestamp: now,
            previous: Vec::new(),
            signers: vec![
                TestSigner {
                    id: keys[0].id(),
                    sk: keys[0].clone(),
                },
                TestSigner {
                    id: keys[1].id(),
                    sk: keys[4].clone(),
                },
                TestSigner {
                    id: keys[2].id(),
                    sk: keys[2].clone(),
                },
            ],
            actions: vec![
                TestAction {
                    key: keys[1].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now,
                },
                TestAction {
                    key: keys[2].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Recovery,
                    actionable: Actionable::CreateKey,
                    effective_from: now,
                },
            ],
            error: Err(SelfError::SiggraphOperationSignatureInvalid),
        }];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_signature_missing() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![TestOperation {
            id: keys[0].clone(),
            version: 2,
            sequence: 0,
            timestamp: now,
            previous: Vec::new(),
            signers: vec![
                TestSigner {
                    id: keys[0].id(),
                    sk: keys[0].clone(),
                },
                TestSigner {
                    id: keys[2].id(),
                    sk: keys[2].clone(),
                },
            ],
            actions: vec![
                TestAction {
                    key: keys[1].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now,
                },
                TestAction {
                    key: keys[2].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Recovery,
                    actionable: Actionable::CreateKey,
                    effective_from: now,
                },
            ],
            error: Err(SelfError::SiggraphOperationNotEnoughSigners),
        }];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_key_signing_duplicate() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[1].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 1,
                }],
                error: Err(SelfError::SiggraphActionKeyDuplicate),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_key_signing_revocation() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        // revoke the only signing key
        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![TestSigner {
                    id: keys[1].id(),
                    sk: keys[1].clone(),
                }],
                actions: vec![TestAction {
                    key: keys[1].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::RevokeKey,
                    effective_from: now + 1,
                }],
                error: Err(SelfError::SiggraphOperationNoValidKeys),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_key_recovery_revocation() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        // revoke the only signing key
        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![TestSigner {
                    id: keys[1].id(),
                    sk: keys[1].clone(),
                }],
                actions: vec![TestAction {
                    key: keys[2].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::RevokeKey,
                    effective_from: now + 1,
                }],
                error: Err(SelfError::SiggraphOperationNoValidRecoveryKey),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_key_recovery_duplicate() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        // revoke the only signing key
        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[4].id(),
                        sk: keys[4].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[4].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Recovery,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 1,
                }],
                error: Err(SelfError::SiggraphActionMultipleActiveRecoveryKeys),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_signature_signer_revoked() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        // revoke the only signing key
        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[3].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![TestSigner {
                    id: keys[1].id(),
                    sk: keys[1].clone(),
                }],
                actions: vec![TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::RevokeKey,
                    effective_from: now + 1,
                }],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 2,
                timestamp: now + 2,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                    TestSigner {
                        id: keys[4].id(),
                        sk: keys[4].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[4].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 2,
                }],
                error: Err(SelfError::SiggraphOperationSignatureKeyRevoked),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_signature_signer_unauthorized() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        // revoke the only signing key
        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![TestSigner {
                    id: keys[4].id(),
                    sk: keys[4].clone(),
                }],
                actions: vec![TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 1,
                }],
                error: Err(SelfError::SiggraphOperationSigningKeyInvalid),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_actions_empty() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        // revoke the only signing key
        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![TestSigner {
                    id: keys[1].id(),
                    sk: keys[1].clone(),
                }],
                actions: vec![],
                error: Err(SelfError::SiggraphOperationNOOP),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_action_revoke_duplicate() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        // revoke the only signing key
        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[3].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![TestSigner {
                    id: keys[1].id(),
                    sk: keys[1].clone(),
                }],
                actions: vec![TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Recovery,
                    actionable: Actionable::RevokeKey,
                    effective_from: now + 1,
                }],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 2,
                timestamp: now + 2,
                previous: Vec::new(),
                signers: vec![TestSigner {
                    id: keys[1].id(),
                    sk: keys[1].clone(),
                }],
                actions: vec![TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Recovery,
                    actionable: Actionable::RevokeKey,
                    effective_from: now + 2,
                }],
                error: Err(SelfError::SiggraphActionKeyAlreadyRevoked),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_action_revoke_reference() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        // revoke the only signing key
        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![TestSigner {
                    id: keys[1].id(),
                    sk: keys[1].clone(),
                }],
                actions: vec![TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Recovery,
                    actionable: Actionable::RevokeKey,
                    effective_from: now + 1,
                }],
                error: Err(SelfError::SiggraphActionKeyMissing),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_action_revoke_root() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        // revoke the only signing key
        let mut test_history = vec![TestOperation {
            id: keys[0].clone(),
            version: 2,
            sequence: 0,
            timestamp: now,
            previous: Vec::new(),
            signers: vec![
                TestSigner {
                    id: keys[0].id(),
                    sk: keys[0].clone(),
                },
                TestSigner {
                    id: keys[1].id(),
                    sk: keys[1].clone(),
                },
                TestSigner {
                    id: keys[2].id(),
                    sk: keys[2].clone(),
                },
                TestSigner {
                    id: keys[3].id(),
                    sk: keys[3].clone(),
                },
            ],
            actions: vec![
                TestAction {
                    key: keys[1].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now,
                },
                TestAction {
                    key: keys[2].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Recovery,
                    actionable: Actionable::CreateKey,
                    effective_from: now,
                },
                TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now,
                },
                TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Recovery,
                    actionable: Actionable::RevokeKey,
                    effective_from: now + 1,
                },
            ],
            error: Err(SelfError::SiggraphActionKeyMissing),
        }];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_action_revoke_timestamp() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        // revoke the only signing key
        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[3].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![TestSigner {
                    id: keys[1].id(),
                    sk: keys[1].clone(),
                }],
                actions: vec![TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Recovery,
                    actionable: Actionable::RevokeKey,
                    effective_from: now - 100,
                }],
                error: Err(SelfError::SiggraphOperationTimestampInvalid),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn is_key_valid() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        // revoke the only signing key
        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::RevokeKey,
                        effective_from: now + 1,
                    },
                    TestAction {
                        key: keys[3].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now + 1,
                    },
                ],
                error: Ok(()),
            },
        ];

        let sg = test_execute(&mut test_history);

        assert!(sg.is_key_valid(&keys[1].id(), now));
        assert!(!sg.is_key_valid(&keys[1].id(), now + 1));
        assert!(!sg.is_key_valid(&keys[1].id(), now + 2));
        assert!(!sg.is_key_valid(&keys[1].id(), now - 1));
        assert!(sg.is_key_valid(&keys[3].id(), now + 1));
        assert!(sg.is_key_valid(&keys[3].id(), now + 2));
        assert!(!sg.is_key_valid(&keys[0].id(), now - 1));
    }
}
