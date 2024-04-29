use flatbuffers::{ForwardsUOffset, Vector};

use crate::error::SelfError;
use crate::hashgraph::{node::Node, node::RoleEntry, operation::OperationBuilder};
use crate::keypair::signing::PublicKey;
use crate::keypair::Algorithm;
use crate::protocol::hashgraph::{
    root_as_signed_operation, Action, Actionable, Description, Operation, Role, Signature,
    SignatureHeader, SignedOperation, Version,
};

use std::borrow::{Borrow, BorrowMut};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

pub struct Hashgraph {
    identifier: Option<Vec<u8>>,
    controller: Option<Vec<u8>>,
    root: Option<Rc<RefCell<Node>>>,
    operations: Vec<Vec<u8>>,
    keys: HashMap<Vec<u8>, Rc<RefCell<Node>>>,
    hashes: HashMap<Vec<u8>, usize>,
    deactivated: bool,
    sig_buf: Vec<u8>,
}

impl Hashgraph {
    /// creates a new empty hashgraph
    pub fn new() -> Hashgraph {
        Hashgraph {
            identifier: None,
            controller: None,
            root: None,
            keys: HashMap::new(),
            hashes: HashMap::new(),
            operations: Vec::new(),
            deactivated: false,
            sig_buf: vec![0; 97],
        }
    }

    /// loads a hashgraph from a collection of operations. validation of signatures can optionally be skipped
    pub fn load(history: &[Vec<u8>], verify: bool) -> Result<Hashgraph, SelfError> {
        let mut sg = Hashgraph {
            identifier: None,
            controller: None,
            root: None,
            keys: HashMap::new(),
            hashes: HashMap::new(),
            operations: Vec::new(),
            deactivated: false,
            sig_buf: vec![0; 97],
        };

        for operation in history {
            sg.execute_operation(operation, verify)?
        }

        Ok(sg)
    }

    pub fn identifier(&self) -> Option<&[u8]> {
        self.identifier
            .as_ref()
            .map(|identifier| identifier.as_ref())
    }

    pub fn controller(&self) -> Option<&[u8]> {
        self.controller
            .as_ref()
            .map(|controller| controller.as_ref())
    }

    pub fn create(&self) -> OperationBuilder {
        let mut ob = OperationBuilder::new();

        ob.sequence(self.operations.len() as u32)
            .timestamp(crate::time::unix());

        if let Some(id) = &self.identifier {
            ob.id(id);
        }

        if let Some(last_op) = self.operations.last() {
            // compute the hash of the last operation
            ob.previous(&crate::crypto::hash::sha3(last_op));
        }

        ob
    }

    pub fn execute(&mut self, operation: Vec<u8>) -> Result<(), SelfError> {
        self.execute_operation(&operation, true)
    }

    pub fn key_valid_at(&self, public_key: &[u8], timeframe: i64) -> bool {
        match self.keys.get(public_key) {
            Some(key) => key.as_ref().borrow().valid_at(timeframe),
            None => false,
        }
    }

    pub fn key_has_roles(&self, public_key: &[u8], roles: u64) -> bool {
        match self.keys.get(public_key) {
            Some(key) => key.as_ref().borrow().has_roles(roles),
            None => false,
        }
    }

    pub fn key_has_roles_at(&self, public_key: &[u8], roles: u64, timeframe: i64) -> bool {
        match self.keys.get(public_key) {
            Some(key) => key.as_ref().borrow().has_roles_at(roles, timeframe),
            None => false,
        }
    }

    fn collect_signers(
        &mut self,
        signed_op: &SignedOperation,
        op: &Operation,
        signers: &mut HashSet<Vec<u8>>,
        verify: bool,
    ) -> Result<(), SelfError> {
        let signatures = signed_op.signatures().unwrap();

        for (i, signature) in signatures.iter().enumerate() {
            let header_data = match signature.header() {
                Some(header_data) => header_data,
                None => return Err(SelfError::HashgraphInvalidSignatureHeader),
            };

            if verify {
                let header_hash = crate::crypto::hash::sha3(header_data.bytes());
                self.sig_buf[65..97].copy_from_slice(&header_hash);
            }

            let header = flatbuffers::root::<SignatureHeader>(header_data.bytes())
                .map_err(|_| SelfError::HashgraphInvalidSignatureHeader)?;

            let signer = match header.signer() {
                Some(signer) => signer,
                None => return Err(SelfError::HashgraphInvalidSignerLength),
            };

            if signer.len() < 33 {
                return Err(SelfError::HashgraphInvalidSignerLength);
            }

            if op.sequence() == 0 && i == 0 {
                // if this is the first signature on the first operation
                // this is the key used as an identifier for the account.
                // copy it to the sig buffer for verifying signatures
                self.identifier = Some(Vec::from(signer.bytes()));
                self.sig_buf[0..33].copy_from_slice(signer.bytes());
            }

            if verify {
                let signature_data = match signature.signature() {
                    Some(signature) => signature,
                    None => return Err(SelfError::HashgraphInvalidSignatureLength),
                };

                if signature_data.len() != 64 {
                    return Err(SelfError::HashgraphInvalidSignatureLength);
                }

                let signers_pk = PublicKey::from_bytes(signer.bytes())?;
                if !signers_pk.verify(&self.sig_buf, signature_data.bytes()) {
                    return Err(SelfError::HashgraphInvalidSignature);
                }

                if signers.contains(signer.bytes()) {
                    return Err(SelfError::HashgraphDuplicateSigner);
                }
            }

            signers.insert(Vec::from(signer.bytes()));
        }

        Ok(())
    }

    fn validate_operation(
        &mut self,
        signed_op: &SignedOperation,
        op: &Operation,
        signers: &mut HashSet<Vec<u8>>,
    ) -> Result<(), SelfError> {
        if self.deactivated {
            return Err(SelfError::HashgraphDeactivated);
        }

        // check the sequence is in order and version of the operation are correct
        if op.sequence() != self.operations.len() as u32 {
            return Err(SelfError::HashgraphOperationSequenceOutOfOrder);
        }

        if op.version() != Version::V0 {
            return Err(SelfError::HashgraphOperationVersionInvalid);
        }

        if let Some(actions) = op.actions() {
            if actions.is_empty() {
                return Err(SelfError::HashgraphOperationNOOP);
            }
        } else {
            return Err(SelfError::HashgraphOperationNOOP);
        }

        let signatures = match signed_op.signatures() {
            Some(signatures) => signatures,
            None => return Err(SelfError::HashgraphOperationUnsigned),
        };

        if op.sequence() == 0 {
            if signatures.len() < 2 {
                return Err(SelfError::HashgraphNotEnoughSigners);
            }
        } else {
            let previous_hash = match op.previous() {
                Some(previous_hash) => previous_hash,
                None => return Err(SelfError::HashgraphInvalidPreviousHash),
            };

            let hash_index = match self.hashes.get(previous_hash.bytes()) {
                Some(hash_index) => hash_index,
                None => return Err(SelfError::HashgraphInvalidPreviousHash),
            };

            if *hash_index != self.operations.len() - 1 {
                return Err(SelfError::HashgraphInvalidPreviousHash);
            }

            let previous_op = self.operation(self.operations.len() - 1);

            if previous_op.timestamp() >= op.timestamp() {
                return Err(SelfError::HashgraphInvalidTimestamp);
            }
        }

        self.collect_signers(signed_op, op, signers, true)
    }

    fn authorize_operation(
        &self,
        op: &Operation,
        signers: &mut HashSet<Vec<u8>>,
    ) -> Result<(), SelfError> {
        if op.sequence() == 0 {
            return Ok(());
        }

        let mut authorized = false;

        for signer in signers.iter() {
            let signing_key = match self.keys.get(signer) {
                Some(signing_key) => signing_key.as_ref().borrow(),
                None => continue,
            };

            // signing key must have capabilityInvocation role to update the document
            if !signing_key.has_roles(Role::Invocation.bits()) {
                return Err(SelfError::HashgraphSignerRoleInvalid);
            }

            if op.timestamp() < signing_key.created_at {
                return Err(SelfError::HashgraphSigningKeyRevoked);
            }

            // check the signing key hasn't been revoked before the operation
            if signing_key.revoked_at != 0 && op.timestamp() > signing_key.revoked_at {
                return Err(SelfError::HashgraphSigningKeyRevoked);
            }

            authorized = true
        }

        if !authorized {
            return Err(SelfError::HashgraphOperationUnauthorized);
        }

        Ok(())
    }

    fn execute_operation(&mut self, op: &[u8], verify: bool) -> Result<(), SelfError> {
        let mut signers = HashSet::new();

        let signed_operation = flatbuffers::root::<SignedOperation>(op)
            .map_err(|_| SelfError::HashgraphOperationInvalid)?;
        let signed_operation_hash = crate::crypto::hash::sha3(op);

        let operation_data = match signed_operation.operation() {
            Some(operation_data) => operation_data,
            None => return Err(SelfError::HashgraphOperationInvalid),
        };

        let operation = flatbuffers::root::<Operation>(operation_data.bytes())
            .map_err(|_| SelfError::HashgraphOperationInvalid)?;

        if operation.actions().is_none() {
            return Err(SelfError::HashgraphOperationNOOP);
        }

        if verify {
            let operation_hash = crate::crypto::hash::sha3(operation_data.bytes());

            // copy the operation hash to ourr temporary buffer we
            // will use to calcuate signatures for each signer
            self.sig_buf[33..65].copy_from_slice(&operation_hash);

            self.validate_operation(&signed_operation, &operation, &mut signers)?;
            self.authorize_operation(&operation, &mut signers)?;
            self.validate_actions(&operation, &mut signers)?;
        } else {
            self.collect_signers(&signed_operation, &operation, &mut signers, false)?;
        }

        self.execute_actions(&operation, &mut signers)?;

        self.hashes
            .insert(signed_operation_hash, self.operations.len());
        self.operations.push(op.to_vec());

        Ok(())
    }

    fn validate_actions(
        &self,
        op: &Operation,
        signers: &mut HashSet<Vec<u8>>,
    ) -> Result<(), SelfError> {
        // references contains a list of any referenced or embedded key
        // and the action that was performed on it
        let mut references = HashMap::new();

        let actions = match op.actions() {
            Some(actions) => actions,
            None => return Err(SelfError::HashgraphOperationNOOP),
        };

        for action in actions.iter() {
            match action.actionable() {
                Actionable::Grant => {
                    self.validate_action_grant(signers, &mut references, &action)?
                }
                Actionable::Modify => self.validate_action_modify(op, &mut references, &action)?,
                Actionable::Revoke => self.validate_action_revoke(op, &mut references, &action)?,
                Actionable::Recover => self.validate_action_recover(op, &mut references)?,
                Actionable::Deactivate => self.validate_action_deactivate(op, &mut references)?,
                _ => return Err(SelfError::HashgraphInvalidAction),
            }
        }

        // check this operation has been signed by keys that actually
        // exist or are created by this operation
        for id in signers.iter() {
            // if this is the identity key, skip it
            if op.sequence() == 0 && self.sig_buf[0..33] == *id {
                continue;
            }

            if let Some((action, _)) = references.get(id) {
                if *action == Actionable::Grant {
                    continue;
                }
            }

            if self.keys.contains_key(id) {
                continue;
            }

            return Err(SelfError::HashgraphSignerUnknown);
        }

        let mut active_keys = false;

        // check that there is still at least one active key with
        // the capability to update the document
        for (id, key) in self.keys.iter() {
            // check if the key is still active
            if key.as_ref().borrow().revoked_at != 0 {
                continue;
            }

            // check the key can update the document
            if !key.as_ref().borrow().has_roles(Role::Invocation.bits()) {
                continue;
            }

            // is this key referenced by any action?
            // is this reference just modifying and not revoking?
            if let Some((action, _)) = references.get(id) {
                if *action == Actionable::Modify || *action == Actionable::Deactivate {
                    active_keys = true;
                    break;
                }
            } else {
                active_keys = true;
                break;
            }
        }

        if active_keys {
            return Ok(());
        }

        // if there are no active existing keys, check for
        // new keys added by the operation
        for (_, (action, roles)) in references.iter() {
            if roles & Role::Invocation.bits() != 0
                && (*action == Actionable::Grant || *action == Actionable::Modify)
            {
                active_keys = true;
                break;
            }
        }

        if !active_keys {
            return Err(SelfError::HashgraphNoActiveKeys);
        }

        Ok(())
    }

    fn execute_actions(
        &mut self,
        op: &Operation,
        signers: &mut HashSet<Vec<u8>>,
    ) -> Result<(), SelfError> {
        let actions = match op.actions() {
            Some(actions) => actions,
            None => return Err(SelfError::HashgraphOperationNOOP),
        };

        for action in actions.iter() {
            match action.actionable() {
                Actionable::Grant => self.execute_action_grant(op, signers, &action)?,
                Actionable::Modify => self.execute_action_modify(op, &action)?,
                Actionable::Revoke => self.execute_action_revoke(&action)?,
                Actionable::Recover => self.execute_action_recover(&action)?,
                Actionable::Deactivate => self.execute_action_deactivate(&action)?,
                _ => return Err(SelfError::HashgraphInvalidAction),
            }
        }

        Ok(())
    }

    fn validate_action_grant(
        &self,
        signers: &mut HashSet<Vec<u8>>,
        references: &mut HashMap<Vec<u8>, (Actionable, u64)>,
        action: &Action,
    ) -> Result<(), SelfError> {
        match action.description_type() {
            Description::Embedded => {
                if let Some(embedded) = action.description_as_embedded() {
                    let id = match embedded.id() {
                        Some(id) => id,
                        None => return Err(SelfError::HashgraphInvalidKeyLength),
                    };

                    if id.len() != 33 {
                        return Err(SelfError::HashgraphInvalidKeyLength);
                    }

                    // check that the key has self signed the operation
                    // if it can sign the operation
                    if !signers.contains(id.bytes()) && id.get(0) == 0 {
                        return Err(SelfError::HashgraphSelfSignatureRequired);
                    }

                    // check this embedded key does not already exist
                    if self.keys.contains_key(id.bytes()) {
                        return Err(SelfError::HashgraphDuplicateKey);
                    }

                    if action.roles() == 0 {
                        return Err(SelfError::HashgraphNoRolesAssigned);
                    }

                    let mut uses: u64 = 0;

                    for role in 1..6 {
                        if 1 << role == Role::Verification.bits() {
                            // we're not checking if this is a multi-role key here
                            continue;
                        }

                        if action.roles() & 1 << role != 0 {
                            uses += 1;
                        }
                    }

                    // if an embedded key has more than one role and it isn't a verification key
                    // that can have multiple uses, then error
                    if uses > 1 && action.roles() & Role::Verification.bits() == 0 {
                        return Err(SelfError::HashgraphMultiRoleKeyViolation);
                    }

                    if references.contains_key(id.bytes()) {
                        return Err(SelfError::HashgraphDuplicateAction);
                    }

                    references.insert(Vec::from(id.bytes()), (Actionable::Grant, action.roles()));
                }
            }
            Description::Reference => {
                if let Some(reference) = action.description_as_reference() {
                    let id = match reference.id() {
                        Some(id) => id,
                        None => return Err(SelfError::HashgraphInvalidKeyLength),
                    };

                    if id.len() != 33 {
                        return Err(SelfError::HashgraphInvalidKeyLength);
                    }

                    let controller = match reference.controller() {
                        Some(controller) => controller,
                        None => return Err(SelfError::HashgraphInvalidControllerLength),
                    };

                    if controller.len() != 33 {
                        return Err(SelfError::HashgraphInvalidControllerLength);
                    }

                    // check that the key has self signed the operation
                    if !signers.contains(id.bytes()) {
                        return Err(SelfError::HashgraphSelfSignatureRequired);
                    }

                    // check this embedded key does not already exist
                    if self.keys.contains_key(id.bytes()) {
                        return Err(SelfError::HashgraphDuplicateKey);
                    }

                    if action.roles() == 0 {
                        return Err(SelfError::HashgraphNoRolesAssigned);
                    }

                    if references.contains_key(id.bytes()) {
                        return Err(SelfError::HashgraphDuplicateAction);
                    }

                    references.insert(Vec::from(id.bytes()), (Actionable::Grant, action.roles()));
                }
            }
            _ => return Err(SelfError::HashgraphInvalidDescription),
        }

        Ok(())
    }

    fn execute_action_grant(
        &mut self,
        op: &Operation,
        signers: &mut HashSet<Vec<u8>>,
        action: &Action,
    ) -> Result<(), SelfError> {
        match action.description_type() {
            Description::Embedded => {
                if let Some(embedded) = action.description_as_embedded() {
                    let id = match embedded.id() {
                        Some(id) => id,
                        None => return Err(SelfError::HashgraphInvalidKeyLength),
                    };

                    let controller = embedded
                        .controller()
                        .map(|controller| Vec::from(controller.bytes()));

                    let node = Rc::new(RefCell::new(Node {
                        controller,
                        sequence: op.sequence(),
                        roles: vec![RoleEntry {
                            role: action.roles(),
                            from: op.timestamp(),
                        }],
                        public_key: PublicKey::from_bytes(id.bytes())?,
                        created_at: op.timestamp(),
                        revoked_at: 0,
                        incoming: Vec::new(),
                        outgoing: Vec::new(),
                    }));

                    // link it to the signing keys that created it, unless it's
                    // a self signed signature
                    for signer in signers.iter() {
                        if op.sequence() == 0 && self.root.is_none() {
                            if signer == id.bytes()
                                && self
                                    .identifier
                                    .as_ref()
                                    .is_some_and(|identifier| identifier != id.bytes())
                            {
                                self.root = Some(node.clone())
                            }
                            continue;
                        }

                        if id.bytes() == signer {
                            // this is a self signed signature, skip it
                            continue;
                        }

                        let parent = match self.keys.get(signer) {
                            Some(parent) => parent,
                            None => {
                                if op.sequence() == 0 {
                                    // this is the signature by the identifier key, skip it
                                    continue;
                                }

                                return Err(SelfError::HashgraphSignerUnknown);
                            }
                        };

                        if !parent.as_ref().borrow().has_roles(Role::Invocation.bits()) {
                            // if the signer isn't the authorizing the operation
                            // then dont link it to our new key
                            continue;
                        }

                        node.as_ref().borrow_mut().incoming.push((*parent).clone());
                        parent.as_ref().borrow_mut().outgoing.push(node.clone());
                    }

                    self.keys.insert(Vec::from(id.bytes()), node);
                }
            }
            Description::Reference => {
                if let Some(reference) = action.description_as_reference() {
                    let id = match reference.id() {
                        Some(id) => id,
                        None => return Err(SelfError::HashgraphInvalidKeyLength),
                    };

                    let controller = match reference.controller() {
                        Some(controller) => Vec::from(controller.bytes()),
                        None => return Err(SelfError::HashgraphInvalidControllerLength),
                    };

                    let node = Rc::new(RefCell::new(Node {
                        controller: Some(controller),
                        sequence: op.sequence(),
                        roles: vec![RoleEntry {
                            role: action.roles(),
                            from: op.timestamp(),
                        }],
                        public_key: PublicKey::from_bytes(id.bytes())?,
                        created_at: op.timestamp(),
                        revoked_at: 0,
                        incoming: Vec::new(),
                        outgoing: Vec::new(),
                    }));

                    // link it to the signing keys that created it, unless it's
                    // a self signed signature
                    for signer in signers.iter() {
                        if op.sequence() == 0 && self.root.is_none() {
                            if signer == id.bytes()
                                && self
                                    .identifier
                                    .as_ref()
                                    .is_some_and(|identifier| identifier != id.bytes())
                            {
                                self.root = Some(node.clone())
                            }
                            continue;
                        }

                        if id.bytes() == signer {
                            // this is a self signed signature, skip it
                            continue;
                        }

                        let parent = match self.keys.get(signer) {
                            Some(parent) => parent,
                            None => {
                                if op.sequence() == 0 {
                                    // this is the signature by the identifier key, skip it
                                    continue;
                                }

                                return Err(SelfError::HashgraphSignerUnknown);
                            }
                        };

                        node.as_ref().borrow_mut().incoming.push((*parent).clone());
                        parent.as_ref().borrow_mut().outgoing.push(node.clone());
                    }

                    self.keys.insert(Vec::from(id.bytes()), node);
                }
            }
            _ => return Err(SelfError::HashgraphInvalidDescription),
        }

        Ok(())
    }

    fn validate_action_revoke(
        &self,
        op: &Operation,
        references: &mut HashMap<Vec<u8>, (Actionable, u64)>,
        action: &Action,
    ) -> Result<(), SelfError> {
        if op.sequence() == 0 {
            return Err(SelfError::HashgraphInvalidRevoke);
        }

        match action.description_type() {
            Description::Embedded => return Err(SelfError::HashgraphInvalidEmbeddedDescription),
            Description::Reference => {
                if let Some(reference) = action.description_as_reference() {
                    let id = match reference.id() {
                        Some(id) => id,
                        None => return Err(SelfError::HashgraphInvalidKeyLength),
                    };

                    if id.len() != 33 {
                        return Err(SelfError::HashgraphInvalidKeyLength);
                    }

                    if let Some(controller) = reference.controller() {
                        if controller.len() != 33 {
                            return Err(SelfError::HashgraphInvalidControllerLength);
                        }
                    }

                    // check this embedded key does not already exist
                    let key = match self.keys.get(id.bytes()) {
                        Some(key) => key.as_ref().borrow(),
                        None => return Err(SelfError::HashgraphReferencedDescriptionNotFound),
                    };

                    if key.revoked_at != 0 {
                        return Err(SelfError::HashgraphKeyAlreadyRevoked);
                    }

                    if key.created_at > action.from() {
                        return Err(SelfError::HashgraphInvalidRevocationTimestamp);
                    }

                    if references.contains_key(id.bytes()) {
                        return Err(SelfError::HashgraphDuplicateAction);
                    }

                    references.insert(Vec::from(id.bytes()), (Actionable::Revoke, 0));
                }
            }
            _ => return Err(SelfError::HashgraphInvalidDescription),
        }

        Ok(())
    }

    fn execute_action_revoke(&mut self, action: &Action) -> Result<(), SelfError> {
        if let Some(reference) = action.description_as_reference() {
            let id = match reference.id() {
                Some(id) => id,
                None => return Err(SelfError::HashgraphInvalidKeyLength),
            };

            let key = match self.keys.get_mut(id.bytes()) {
                Some(key) => key,
                None => return Err(SelfError::HashgraphReferencedDescriptionNotFound),
            };

            key.as_ref().borrow_mut().revoked_at = action.from();

            // revoke all child keys created after the
            // time the revocation takes effect
            for child in key.as_ref().borrow().collect() {
                let mut borrowed_child = child.as_ref().borrow_mut();

                if borrowed_child.created_at >= action.from() {
                    borrowed_child.revoked_at = action.from();
                }
            }
        }

        Ok(())
    }

    fn validate_action_modify(
        &self,
        op: &Operation,
        references: &mut HashMap<Vec<u8>, (Actionable, u64)>,
        action: &Action,
    ) -> Result<(), SelfError> {
        if op.sequence() == 0 {
            return Err(SelfError::HashgraphInvalidModify);
        }

        match action.description_type() {
            Description::Embedded => return Err(SelfError::HashgraphInvalidEmbeddedDescription),
            Description::Reference => {
                if let Some(reference) = action.description_as_reference() {
                    let id = match reference.id() {
                        Some(id) => id,
                        None => return Err(SelfError::HashgraphInvalidKeyLength),
                    };

                    if id.len() != 33 {
                        return Err(SelfError::HashgraphInvalidKeyLength);
                    }

                    if let Some(controller) = reference.controller() {
                        if controller.len() != 33 {
                            return Err(SelfError::HashgraphInvalidControllerLength);
                        }
                    }

                    // check this embedded key does not already exist
                    let key = match self.keys.get(id.bytes()) {
                        Some(key) => key.as_ref().borrow_mut(),
                        None => return Err(SelfError::HashgraphReferencedDescriptionNotFound),
                    };

                    if action.roles() == 0 {
                        return Err(SelfError::HashgraphNoRolesAssigned);
                    }

                    if let Some(roles) = key.roles.last() {
                        if roles.role == action.roles() {
                            return Err(SelfError::HashgraphModifyNOOP);
                        }

                        if !key.has_roles(Role::Verification.bits()) {
                            return Err(SelfError::HashgraphInvalidKeyReuse);
                        }
                    }

                    if key.revoked_at != 0 {
                        return Err(SelfError::HashgraphKeyAlreadyRevoked);
                    }

                    if references.contains_key(id.bytes()) {
                        return Err(SelfError::HashgraphDuplicateAction);
                    }

                    references.insert(Vec::from(id.bytes()), (Actionable::Modify, action.roles()));
                }
            }
            _ => return Err(SelfError::HashgraphInvalidDescription),
        }

        Ok(())
    }

    fn execute_action_modify(&mut self, op: &Operation, action: &Action) -> Result<(), SelfError> {
        if let Some(reference) = action.description_as_reference() {
            let id = match reference.id() {
                Some(id) => id,
                None => return Err(SelfError::HashgraphInvalidKeyLength),
            };

            let key = match self.keys.get_mut(id.bytes()) {
                Some(key) => key,
                None => return Err(SelfError::HashgraphReferencedDescriptionNotFound),
            };

            key.as_ref().borrow_mut().roles.push(RoleEntry {
                from: op.timestamp(),
                role: action.roles(),
            });
        }

        Ok(())
    }

    fn validate_action_recover(
        &self,
        op: &Operation,
        references: &mut HashMap<Vec<u8>, (Actionable, u64)>,
    ) -> Result<(), SelfError> {
        if op.sequence() == 0 {
            return Err(SelfError::HashgraphInvalidRecover);
        }

        let root = match &self.root {
            Some(root) => root.as_ref().borrow(),
            None => return Err(SelfError::HashgraphInvalidState),
        };

        if root.revoked_at == 0 {
            if references.contains_key(root.public_key.address()) {
                return Err(SelfError::HashgraphDuplicateAction);
            }

            references.insert(root.public_key.address().to_vec(), (Actionable::Recover, 0));
        }

        for child in root.collect().iter() {
            let borrowed_child = child.as_ref().borrow();

            if borrowed_child.revoked_at == 0 {
                if references.contains_key(borrowed_child.public_key.address()) {
                    return Err(SelfError::HashgraphDuplicateAction);
                }

                references.insert(root.public_key.address().to_vec(), (Actionable::Recover, 0));
            }
        }

        Ok(())
    }

    fn execute_action_recover(&mut self, action: &Action) -> Result<(), SelfError> {
        let mut root = match &self.root {
            Some(root) => root.as_ref().borrow_mut(),
            None => return Err(SelfError::HashgraphInvalidState),
        };

        if root.revoked_at == 0 {
            root.revoked_at = action.from();
        }

        for child in root.collect().iter() {
            let mut borrowed_child = child.as_ref().borrow_mut();

            if borrowed_child.revoked_at == 0 {
                borrowed_child.revoked_at = action.from();
            }
        }

        Ok(())
    }

    fn validate_action_deactivate(
        &self,
        op: &Operation,
        references: &mut HashMap<Vec<u8>, (Actionable, u64)>,
    ) -> Result<(), SelfError> {
        if op.sequence() == 0 {
            return Err(SelfError::HashgraphInvalidRecover);
        }

        let root = match &self.root {
            Some(root) => root.as_ref().borrow(),
            None => return Err(SelfError::HashgraphInvalidState),
        };

        if root.revoked_at == 0 {
            if references.contains_key(root.public_key.address()) {
                return Err(SelfError::HashgraphDuplicateAction);
            }

            references.insert(
                root.public_key.address().to_vec(),
                (Actionable::Deactivate, 0),
            );
        }

        for child in root.collect().iter() {
            let borrowed_child = child.as_ref().borrow();

            if borrowed_child.revoked_at == 0 {
                if references.contains_key(borrowed_child.public_key.address()) {
                    return Err(SelfError::HashgraphDuplicateAction);
                }

                references.insert(
                    root.public_key.address().to_vec(),
                    (Actionable::Deactivate, 0),
                );
            }
        }

        Ok(())
    }

    fn execute_action_deactivate(&mut self, action: &Action) -> Result<(), SelfError> {
        let mut root = match &self.root {
            Some(root) => root.as_ref().borrow_mut(),
            None => return Err(SelfError::HashgraphInvalidState),
        };

        if root.revoked_at == 0 {
            root.revoked_at = action.from();
        }

        for child in root.collect().iter() {
            let mut borrowed_child = child.as_ref().borrow_mut();

            if borrowed_child.revoked_at == 0 {
                borrowed_child.revoked_at = action.from();
            }
        }

        self.deactivated = true;

        Ok(())
    }

    fn operation(&self, index: usize) -> Operation {
        let signed_op = root_as_signed_operation(&self.operations[index]).unwrap();
        let op_bytes = signed_op.operation().unwrap();
        flatbuffers::root::<Operation>(op_bytes.bytes()).unwrap()
    }
}

impl Default for Hashgraph {
    fn default() -> Self {
        Hashgraph::new()
    }
}

#[cfg(test)]
mod tests {
    use super::Hashgraph;
    use crate::error::SelfError;
    use crate::keypair::signing::KeyPair;
    use crate::keypair::{exchange, signing};
    use crate::protocol::hashgraph;

    #[test]
    fn operation_single_valid() {
        let mut graph = Hashgraph::new();

        let identifier_key = signing::KeyPair::new();
        let invocation_key = signing::KeyPair::new();
        let authentication_key = signing::KeyPair::new();
        let assertion_key = signing::KeyPair::new();
        let agreement_key = exchange::KeyPair::new();

        let operation = graph
            .create()
            .id(identifier_key.address())
            .grant_embedded(invocation_key.address(), hashgraph::Role::Invocation)
            .grant_embedded(
                authentication_key.address(),
                hashgraph::Role::Authentication,
            )
            .grant_embedded(assertion_key.address(), hashgraph::Role::Assertion)
            .grant_embedded(agreement_key.address(), hashgraph::Role::KeyAgreement)
            .sign(&identifier_key)
            .sign(&invocation_key)
            .sign(&authentication_key)
            .sign(&assertion_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");
    }

    #[test]
    fn operation_multi_valid() {
        let mut graph = Hashgraph::new();

        let identifier_key = signing::KeyPair::new();
        let invocation_key = signing::KeyPair::new();
        let authentication_key = signing::KeyPair::new();
        let assertion_key = signing::KeyPair::new();
        let multirole_key = signing::KeyPair::new();
        let agreement_key = exchange::KeyPair::new();

        let now = crate::time::unix();

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now)
            .grant_embedded(invocation_key.address(), hashgraph::Role::Invocation)
            .grant_embedded(
                authentication_key.address(),
                hashgraph::Role::Authentication,
            )
            .grant_embedded(assertion_key.address(), hashgraph::Role::Assertion)
            .grant_embedded(agreement_key.address(), hashgraph::Role::KeyAgreement)
            .sign(&identifier_key)
            .sign(&invocation_key)
            .sign(&authentication_key)
            .sign(&assertion_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .grant_embedded(
                multirole_key.address(),
                hashgraph::Role::Verification | hashgraph::Role::Authentication,
            )
            .sign(&invocation_key)
            .sign(&multirole_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 2)
            .modify(
                multirole_key.address(),
                hashgraph::Role::Verification
                    | hashgraph::Role::Authentication
                    | hashgraph::Role::Assertion
                    | hashgraph::Role::Invocation,
            )
            .revoke(invocation_key.address(), Some(now + 2))
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");
    }

    #[test]
    fn operation_recovery_valid() {
        let mut graph = Hashgraph::new();

        let identifier_key = signing::KeyPair::new();
        let invocation_key = signing::KeyPair::new();
        let recovery_key = signing::KeyPair::new();

        let now = crate::time::unix();

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now)
            .grant_embedded(invocation_key.address(), hashgraph::Role::Invocation)
            .sign(&identifier_key)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .recover(Some(now + 1))
            .grant_embedded(recovery_key.address(), hashgraph::Role::Invocation)
            .sign(&invocation_key)
            .sign(&recovery_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");
    }

    #[test]
    fn operation_deactivate_valid() {
        let mut graph = Hashgraph::new();

        let identifier_key = signing::KeyPair::new();
        let invocation_key = signing::KeyPair::new();

        let now = crate::time::unix();

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now)
            .grant_embedded(invocation_key.address(), hashgraph::Role::Invocation)
            .sign(&identifier_key)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .deactivate(Some(now + 1))
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");
    }

    #[test]
    fn operation_grant_valid() {
        let mut graph = Hashgraph::new();

        let identifier_key = signing::KeyPair::new();
        let invocation_key = signing::KeyPair::new();
        let authenticaton_key = signing::KeyPair::new();

        let now = crate::time::unix();

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now)
            .grant_embedded(invocation_key.address(), hashgraph::Role::Invocation)
            .sign(&identifier_key)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .grant_embedded(authenticaton_key.address(), hashgraph::Role::Authentication)
            .sign(&invocation_key)
            .sign(&authenticaton_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");
    }

    #[test]
    fn operation_modify_valid() {
        let mut graph = Hashgraph::new();

        let identifier_key = signing::KeyPair::new();
        let invocation_key = signing::KeyPair::new();
        let multirole_key = signing::KeyPair::new();

        let now = crate::time::unix();

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now)
            .grant_embedded(invocation_key.address(), hashgraph::Role::Invocation)
            .grant_embedded(
                multirole_key.address(),
                hashgraph::Role::Verification | hashgraph::Role::Authentication,
            )
            .sign(&identifier_key)
            .sign(&invocation_key)
            .sign(&multirole_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .modify(
                multirole_key.address(),
                hashgraph::Role::Verification | hashgraph::Role::Assertion,
            )
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");
    }

    #[test]
    fn operation_revoke_valid() {
        let mut graph = Hashgraph::new();

        let identifier_key = signing::KeyPair::new();
        let invocation_key = signing::KeyPair::new();
        let assertion_key = signing::KeyPair::new();

        let now = crate::time::unix();

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now)
            .grant_embedded(invocation_key.address(), hashgraph::Role::Invocation)
            .grant_embedded(assertion_key.address(), hashgraph::Role::Assertion)
            .sign(&identifier_key)
            .sign(&invocation_key)
            .sign(&assertion_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .revoke(assertion_key.address(), Some(now + 1))
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");
    }

    #[test]
    fn operation_sequence_invalid() {
        let mut graph = Hashgraph::new();

        let identifier_key = signing::KeyPair::new();
        let invocation_key = signing::KeyPair::new();
        let authenticaton_key = signing::KeyPair::new();

        let now = crate::time::unix();

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now)
            .grant_embedded(invocation_key.address(), hashgraph::Role::Invocation)
            .sign(&identifier_key)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        let operation = graph
            .create()
            .id(identifier_key.address())
            .sequence(2)
            .timestamp(now + 1)
            .grant_embedded(authenticaton_key.address(), hashgraph::Role::Authentication)
            .sign(&invocation_key)
            .sign(&authenticaton_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphOperationSequenceOutOfOrder,
        );
    }

    #[test]
    fn operation_timestamp_invalid() {
        let mut graph = Hashgraph::new();

        let identifier_key = signing::KeyPair::new();
        let invocation_key = signing::KeyPair::new();
        let authenticaton_key = signing::KeyPair::new();

        let now = crate::time::unix();

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now)
            .grant_embedded(invocation_key.address(), hashgraph::Role::Invocation)
            .sign(&identifier_key)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now)
            .grant_embedded(authenticaton_key.address(), hashgraph::Role::Authentication)
            .sign(&invocation_key)
            .sign(&authenticaton_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphInvalidTimestamp,
        );

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now - 1)
            .grant_embedded(authenticaton_key.address(), hashgraph::Role::Authentication)
            .sign(&invocation_key)
            .sign(&authenticaton_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphInvalidTimestamp,
        );
    }

    #[test]
    fn operation_previous_hash_invalid() {
        let mut graph = Hashgraph::new();

        let identifier_key = signing::KeyPair::new();
        let invocation_key = signing::KeyPair::new();
        let authenticaton_key = signing::KeyPair::new();

        let now = crate::time::unix();

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now)
            .grant_embedded(invocation_key.address(), hashgraph::Role::Invocation)
            .sign(&identifier_key)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        let invalid_previous_hash = vec![0; 32];

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .previous(&invalid_previous_hash)
            .grant_embedded(authenticaton_key.address(), hashgraph::Role::Authentication)
            .sign(&invocation_key)
            .sign(&authenticaton_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphInvalidPreviousHash,
        );
    }

    #[test]
    fn operation_signature_invalid() {
        let mut graph = Hashgraph::new();

        let identifier_key = signing::KeyPair::new();
        let invocation_key = signing::KeyPair::new();
        let authenticaton_key = signing::KeyPair::new();
        let other_key = signing::KeyPair::new();

        let now = crate::time::unix();

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now)
            .grant_embedded(invocation_key.address(), hashgraph::Role::Invocation)
            .sign(&identifier_key)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        let bad_signing_key =
            KeyPair::from_parts(invocation_key.public().to_owned(), other_key.secret());

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .grant_embedded(authenticaton_key.address(), hashgraph::Role::Authentication)
            .sign(&bad_signing_key)
            .sign(&authenticaton_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphInvalidSignature,
        );

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .grant_embedded(authenticaton_key.address(), hashgraph::Role::Authentication)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphSelfSignatureRequired,
        );

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .grant_embedded(authenticaton_key.address(), hashgraph::Role::Authentication)
            .sign(&invocation_key)
            .sign(&authenticaton_key)
            .sign(&authenticaton_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphDuplicateSigner,
        );
    }

    #[test]
    fn operation_signer_invalid() {
        let mut graph = Hashgraph::new();

        let identifier_key = signing::KeyPair::new();
        let invocation_key = signing::KeyPair::new();
        let authenticaton_key = signing::KeyPair::new();
        let assertion_key = signing::KeyPair::new();
        let other_key = signing::KeyPair::new();

        let now = crate::time::unix();

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now)
            .grant_embedded(invocation_key.address(), hashgraph::Role::Invocation)
            .grant_embedded(assertion_key.address(), hashgraph::Role::Assertion)
            .sign(&identifier_key)
            .sign(&invocation_key)
            .sign(&assertion_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        let bad_signing_key =
            KeyPair::from_parts(other_key.public().to_owned(), invocation_key.secret());

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .grant_embedded(authenticaton_key.address(), hashgraph::Role::Authentication)
            .sign(&bad_signing_key)
            .sign(&authenticaton_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphInvalidSignature,
        );

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .grant_embedded(authenticaton_key.address(), hashgraph::Role::Authentication)
            .sign(&invocation_key)
            .sign(&assertion_key)
            .sign(&authenticaton_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphSignerRoleInvalid,
        );
    }

    #[test]
    fn operation_authorization_invalid() {
        let mut graph = Hashgraph::new();

        let identifier_key = signing::KeyPair::new();
        let invocation_key = signing::KeyPair::new();
        let replacement_key = signing::KeyPair::new();
        let authenticaton_key = signing::KeyPair::new();

        let now = crate::time::unix();

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now)
            .grant_embedded(invocation_key.address(), hashgraph::Role::Invocation)
            .sign(&identifier_key)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .grant_embedded(authenticaton_key.address(), hashgraph::Role::Authentication)
            .sign(&authenticaton_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphOperationUnauthorized,
        );

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .grant_embedded(replacement_key.address(), hashgraph::Role::Invocation)
            .revoke(invocation_key.address(), None)
            .sign(&invocation_key)
            .sign(&replacement_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 2)
            .grant_embedded(authenticaton_key.address(), hashgraph::Role::Authentication)
            .sign(&invocation_key)
            .sign(&authenticaton_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphSigningKeyRevoked,
        );
    }

    #[test]
    fn operation_grant_invalid() {
        let mut graph = Hashgraph::new();

        let identifier_key = signing::KeyPair::new();
        let invocation_key = signing::KeyPair::new();
        let duplicate_key = signing::KeyPair::new();

        let now = crate::time::unix();

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now)
            .grant_embedded(invocation_key.address(), hashgraph::Role::Invocation)
            .sign(&identifier_key)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        // grant same key twice
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .grant_embedded(invocation_key.address(), hashgraph::Role::Invocation)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphDuplicateKey,
        );

        // grant same key twice in the same operation
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .grant_embedded(duplicate_key.address(), hashgraph::Role::Assertion)
            .grant_embedded(duplicate_key.address(), hashgraph::Role::Assertion)
            .sign(&invocation_key)
            .sign(&duplicate_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphDuplicateAction,
        );

        // grant a key with multiple roles, but not a verification method
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .grant_embedded(
                duplicate_key.address(),
                hashgraph::Role::Assertion | hashgraph::Role::Authentication,
            )
            .sign(&invocation_key)
            .sign(&duplicate_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphMultiRoleKeyViolation,
        );

        // deactivate the account
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .deactivate(None)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        // grant on a deactivated account
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 2)
            .grant_embedded(duplicate_key.address(), hashgraph::Role::Assertion)
            .sign(&invocation_key)
            .sign(&duplicate_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphDeactivated,
        );
    }

    #[test]
    fn operation_revoke_invalid() {
        let mut graph = Hashgraph::new();

        let identifier_key = signing::KeyPair::new();
        let invocation_key = signing::KeyPair::new();
        let assertion_key = signing::KeyPair::new();
        let revoked_key = signing::KeyPair::new();
        let unknown_key = signing::KeyPair::new();

        let now = crate::time::unix();

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now)
            .grant_embedded(invocation_key.address(), hashgraph::Role::Invocation)
            .grant_embedded(assertion_key.address(), hashgraph::Role::Assertion)
            .grant_embedded(revoked_key.address(), hashgraph::Role::Authentication)
            .sign(&identifier_key)
            .sign(&invocation_key)
            .sign(&assertion_key)
            .sign(&revoked_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .revoke(assertion_key.address(), None)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        // revoke a non-existant key
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 2)
            .revoke(unknown_key.address(), None)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphReferencedDescriptionNotFound,
        );

        // revoke the same key twice
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 2)
            .revoke(assertion_key.address(), None)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphKeyAlreadyRevoked,
        );

        // revoke the same key twice in the same operation
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 2)
            .revoke(revoked_key.address(), None)
            .revoke(revoked_key.address(), None)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphDuplicateAction,
        );

        // revoke all keys
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 2)
            .revoke(invocation_key.address(), None)
            .revoke(revoked_key.address(), None)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphNoActiveKeys,
        );

        // deactivate the account
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 2)
            .deactivate(None)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        // revoke on a deactivated account
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 3)
            .revoke(revoked_key.address(), None)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphDeactivated,
        );
    }

    #[test]
    fn operation_modify_invalid() {
        let mut graph = Hashgraph::new();

        let identifier_key = signing::KeyPair::new();
        let invocation_key = signing::KeyPair::new();
        let modified_key = signing::KeyPair::new();
        let verification_key = signing::KeyPair::new();
        let unknown_key = signing::KeyPair::new();

        let now = crate::time::unix();

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now)
            .grant_embedded(invocation_key.address(), hashgraph::Role::Invocation)
            .grant_embedded(modified_key.address(), hashgraph::Role::Assertion)
            .grant_embedded(verification_key.address(), hashgraph::Role::Verification)
            .sign(&identifier_key)
            .sign(&invocation_key)
            .sign(&modified_key)
            .sign(&verification_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        // modify a non-existent key
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .modify(unknown_key.address(), hashgraph::Role::Invocation)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphReferencedDescriptionNotFound,
        );

        // modify the same key twice in an operation
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .modify(
                verification_key.address(),
                hashgraph::Role::Verification | hashgraph::Role::Invocation,
            )
            .modify(
                verification_key.address(),
                hashgraph::Role::Verification | hashgraph::Role::Invocation,
            )
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphDuplicateAction,
        );

        // assign multiple roles to non-verification method
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .modify(
                modified_key.address(),
                hashgraph::Role::Assertion | hashgraph::Role::Authentication,
            )
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphInvalidKeyReuse,
        );

        // assign the same roles to an existing key
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .modify(verification_key.address(), hashgraph::Role::Verification)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphModifyNOOP,
        );

        // revoke a key
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .revoke(verification_key.address(), None)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        // modify the revoked key
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 2)
            .modify(
                verification_key.address(),
                hashgraph::Role::Verification | hashgraph::Role::Authentication,
            )
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphKeyAlreadyRevoked,
        );

        // deactivate the account
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 3)
            .deactivate(None)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        // modify on a deactivated account
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 4)
            .modify(
                modified_key.address(),
                hashgraph::Role::Verification | hashgraph::Role::Authentication,
            )
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphDeactivated,
        );
    }

    #[test]
    fn operation_recover_invalid() {
        let mut graph = Hashgraph::new();

        let identifier_key = signing::KeyPair::new();
        let invocation_key = signing::KeyPair::new();

        let now = crate::time::unix();

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now)
            .grant_embedded(invocation_key.address(), hashgraph::Role::Invocation)
            .sign(&identifier_key)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        // recover twice in the same operation
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .recover(None)
            .recover(None)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphDuplicateAction,
        );

        // recover leaving no active keys
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .recover(None)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphNoActiveKeys,
        );

        // deactivate the account
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .deactivate(None)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        // recover on a deactivated account
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 2)
            .recover(None)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphDeactivated,
        );
    }

    #[test]
    fn operation_deactivate_invalid() {
        let mut graph = Hashgraph::new();

        let identifier_key = signing::KeyPair::new();
        let invocation_key = signing::KeyPair::new();

        let now = crate::time::unix();

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now)
            .grant_embedded(invocation_key.address(), hashgraph::Role::Invocation)
            .sign(&identifier_key)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        // deactivate twice in the same operation
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .deactivate(None)
            .deactivate(None)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphDuplicateAction,
        );

        // deactivate the account
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .deactivate(None)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        // deactivate on a deactivated account
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 2)
            .deactivate(None)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphDeactivated,
        );
    }

    #[test]
    fn operation_actions_invalid() {
        let mut graph = Hashgraph::new();

        let identifier_key = signing::KeyPair::new();
        let invocation_key = signing::KeyPair::new();

        let now = crate::time::unix();

        // initial operation noop
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now)
            .sign(&identifier_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphOperationNOOP,
        );

        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now)
            .grant_embedded(invocation_key.address(), hashgraph::Role::Invocation)
            .sign(&identifier_key)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        graph
            .execute(operation)
            .expect("operation execution failed");

        // deactivate twice in the same operation
        let operation = graph
            .create()
            .id(identifier_key.address())
            .timestamp(now + 1)
            .sign(&invocation_key)
            .build()
            .expect("operation invalid");

        assert_eq!(
            graph.execute(operation).unwrap_err(),
            SelfError::HashgraphOperationNOOP,
        );
    }
}
