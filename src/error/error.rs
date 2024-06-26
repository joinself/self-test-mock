use std::fmt;

#[derive(Debug, PartialEq)]
pub enum SelfError {
    AccountAlreadyConfigured,
    AccountNotConfigured,
    CryptoBoxOpenFailed,
    HashgraphDeactivated,
    HashgraphDuplicateAction,
    HashgraphDuplicateKey,
    HashgraphDuplicateSigner,
    HashgraphInvalidAction,
    HashgraphInvalidControllerLength,
    HashgraphInvalidDescription,
    HashgraphInvalidEmbeddedDescription,
    HashgraphInvalidKeyLength,
    HashgraphInvalidKeyReuse,
    HashgraphInvalidModify,
    HashgraphInvalidPreviousHash,
    HashgraphInvalidRecover,
    HashgraphInvalidRevocationTimestamp,
    HashgraphInvalidRevoke,
    HashgraphInvalidSignature,
    HashgraphInvalidSignatureHeader,
    HashgraphInvalidSignatureLength,
    HashgraphInvalidSignerLength,
    HashgraphInvalidState,
    HashgraphInvalidTimestamp,
    HashgraphKeyAlreadyRevoked,
    HashgraphModifyNOOP,
    HashgraphMultiRoleKeyViolation,
    HashgraphNoActiveKeys,
    HashgraphNoRolesAssigned,
    HashgraphNotEnoughSigners,
    HashgraphOperationInvalid,
    HashgraphOperationMissing,
    HashgraphOperationNOOP,
    HashgraphOperationSequenceOutOfOrder,
    HashgraphOperationUnauthorized,
    HashgraphOperationUnsigned,
    HashgraphOperationVersionInvalid,
    HashgraphReferencedDescriptionNotFound,
    HashgraphSelfSignatureRequired,
    HashgraphSignerRoleInvalid,
    HashgraphSignerUnknown,
    HashgraphSigningKeyRevoked,
    IdentifierEncodingInvalid,
    IdentifierMethodUnsupported,
    KeychainKeyExists,
    KeychainKeyNotFound,
    KeyPairAlgorithmUnknown,
    KeyPairConversionFailed,
    KeyPairDataIncorrectLength,
    KeyPairDecodeInvalidData,
    KeyPairNotFound,
    KeyPairPublicKeyInvalidLength,
    KeyPairSignFailure,
    KeyPairSignMissingSingingKey,
    KeyPairSignWrongKeypairType,
    MessageContentMissing,
    MessageCTIMissing,
    MessageDecodingInvalid,
    MessageEncodingInvalid,
    MessageNoPayload,
    MessageNoProtected,
    MessageNoSignature,
    MessagePayloadInvalid,
    MessageSignatureEncodingInvalid,
    MessageSignatureInvalid,
    MessageSignatureKeypairMismatch,
    MessageSigningKeyInvalid,
    MessageUnsupportedSignatureAlgorithm,
    MessagingDestinationUnknown,
    MessagingGroupUnknown,
    RestRequestConnectionFailed,
    RestRequestConnectionTimeout,
    RestRequestInvalid,
    RestRequestRedirected,
    RestRequestUnknown,
    RestRequestURLInvalid,
    RestResponseBadRequest,
    RestResponseConflict,
    RestResponseNotFound,
    RestResponseUnauthorized,
    RestResponseUnexpected,
    RestResposeBodyInvalid,
    RpcBadGateway,
    RpcBadRequest,
    RpcConflict,
    RpcConnectionFailed,
    RpcConnectionTimeout,
    RpcExpectationFailed,
    RpcForbidden,
    RpcGatewayTimeout,
    RpcGone,
    RpcInternalServerError,
    RpcLengthRequired,
    RpcMethodNotAllowed,
    RpcNotAcceptable,
    RpcNotFound,
    RpcNotImplemented,
    RpcPaymentRequired,
    RpcPreconditionFailed,
    RpcRequestEntityTooLarge,
    RpcRequestFailed,
    RpcRequestTimeout,
    RpcServiceUnavailable,
    RpcUnauthorized,
    RpcUnknown,
    StorageColumnTypeMismatch,
    StorageConnectionFailed,
    StorageSessionNotFound,
    StorageTableCreationFailed,
    StorageTextUtf8Invalid,
    StorageTransactionCommitFailed,
    StorageTransactionCreationFailed,
    StorageTransactionRollbackFailed,
    StorageUnknown,
    TokenEncodingInvalid,
    TokenSignatureInvalid,
    TokenTypeInvalid,
    TokenVersionInvalid,
    WebsocketProtocolEmptyContent,
    WebsocketProtocolEncodingInvalid,
    WebsocketProtocolErrorUnknown,
    WebsocketProtocolRecipientInvalid,
    WebsocketProtocolSenderInvalid,
    WebsocketSenderIdentifierNotOwned,
    WebsocketTokenUnsupported,
}

impl std::error::Error for SelfError {}

impl fmt::Display for SelfError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SelfError::AccountAlreadyConfigured => write!(f, "Account has already been configured"),
            SelfError::AccountNotConfigured => write!(f, "Account has not been configured"),
            SelfError::CryptoBoxOpenFailed => write!(f, "Crypto box could not be decrypted"),
            SelfError::HashgraphDeactivated => write!(f, "Hashgraph has been deactivated and cannot be updated"),
            SelfError::HashgraphDuplicateAction => write!(f, "Hashgraph operation performs more than one action on a key"),
            SelfError::HashgraphDuplicateKey => write!(f, "Hashgraph operation adds a key that already exists"),
            SelfError::HashgraphDuplicateSigner => write!(f, "Hashgraph operation has been signed by the same key more than once"),
            SelfError::HashgraphInvalidAction => write!(f, "Hashgraph action invalid"),
            SelfError::HashgraphInvalidDescription => write!(f, "Hashgraph description invalid"),
            SelfError::HashgraphInvalidControllerLength => write!(f, "Hashgraph controller length invalid"),
            SelfError::HashgraphInvalidEmbeddedDescription => write!(f, "Hashgraph embedded key usage invalid"),
            SelfError::HashgraphInvalidKeyLength => write!(f, "Hashgraph key identifier length invalid"),
            SelfError::HashgraphInvalidKeyReuse => write!(f, "Hashgraph key cannot be assigned additional roles"),
            SelfError::HashgraphInvalidModify => write!(f, "Hashgraph modify action not permitted in initial operation"),
            SelfError::HashgraphInvalidPreviousHash => write!(f, "Hashgraph operation specifies a previous hash that does not match"),
            SelfError::HashgraphInvalidRecover => write!(f, "Hashgraph recover action not permitted in initial operation"),
            SelfError::HashgraphInvalidRevocationTimestamp => write!(f, "Hashgraph revocation timestamp before the target keys creation"),
            SelfError::HashgraphInvalidRevoke => write!(f, "Hashgraph revoke action not permitted in initial operation"),
            SelfError::HashgraphInvalidSignature => write!(f, "Hashgraph operation signature could not be verified"),
            SelfError::HashgraphInvalidSignatureHeader => write!(f, "Hashgraph signature header must be specified"),
            SelfError::HashgraphInvalidSignatureLength => write!(f, "Hashgraph signature length invalid"),
            SelfError::HashgraphInvalidSignerLength => write!(f, "Hashgraph signer length invalid"),
            SelfError::HashgraphInvalidState => write!(f, "Hashgraph is in an invalid state"),
            SelfError::HashgraphInvalidTimestamp => write!(f, "Hashgraph operation timestamp is before the previous operations"),
            SelfError::HashgraphKeyAlreadyRevoked => write!(f, "Hashgraph action revokes an already revoked key"),
            SelfError::HashgraphModifyNOOP => write!(f, "Hashgraph action makes no modification"),
            SelfError::HashgraphMultiRoleKeyViolation => write!(f, "Hashgraph key is not permitted to be assigned to multiple roles"),
            SelfError::HashgraphNoActiveKeys => write!(f, "Hashgraph has no active keys"),
            SelfError::HashgraphNoRolesAssigned => write!(f, "Hashgraph key has no roles assigned"),
            SelfError::HashgraphNotEnoughSigners => write!(f, "Hashgraph operation has not been signed by a sufficient amount of keys"),
            SelfError::HashgraphOperationInvalid => write!(f, "Hashgraph operation invalid"),
            SelfError::HashgraphOperationMissing => write!(f, "Hashgraph operation state has not been specified"),
            SelfError::HashgraphOperationNOOP => write!(f, "Hashgraph operation has no actions"),
            SelfError::HashgraphOperationSequenceOutOfOrder => write!(f, "Hashgraph operation sequence out of order"),
            SelfError::HashgraphOperationUnauthorized => write!(f, "Hashgraph operation must be signed by a key with the correct invocation role"),
            SelfError::HashgraphOperationUnsigned => write!(f, "Hashgraph operation must be signed by an existing valid key"),
            SelfError::HashgraphOperationVersionInvalid => write!(f, "Hashgraph operation version invalid"),
            SelfError::HashgraphReferencedDescriptionNotFound => write!(f, "Hashgraph action references a key that cannot be found"),
            SelfError::HashgraphSelfSignatureRequired => write!(f, "Hashgraph action adds a key that has not signed the operation"),
            SelfError::HashgraphSignerRoleInvalid => write!(f, "Hashgraph operation has been signed by a key that does not have the invocation role"),
            SelfError::HashgraphSignerUnknown => write!(f, "Hashgraph operation has been signed by an unknown key"),
            SelfError::HashgraphSigningKeyRevoked => write!(f, "Hashgraph operation has been signed by a key that has been revoked"),
            SelfError::IdentifierEncodingInvalid => write!(f, "Identifier encoding invalid"),
            SelfError::IdentifierMethodUnsupported => write!(f, "Identifier method unsupported"),
            SelfError::KeychainKeyExists => write!(f, "Keychain key already exists"),
            SelfError::KeychainKeyNotFound => write!(f, "Keychain key not found"),
            SelfError::KeyPairAlgorithmUnknown => write!(f, "Keypair algorithm unsupported"),
            SelfError::KeyPairConversionFailed => write!(f, "Keypair conversion failed"),
            SelfError::KeyPairDataIncorrectLength => write!(f, "Keypair public or secret key data length is incorrect"),
            SelfError::KeyPairDecodeInvalidData => write!(f, "Keypair could not be decoded"),
            SelfError::KeyPairNotFound => write!(f, "Keypair not found"),
            SelfError::KeyPairPublicKeyInvalidLength => write!(f, "Keypair public key is an incorrect length"),
            SelfError::KeyPairSignFailure => write!(f, "Keypair signing failed"),
            SelfError::KeyPairSignMissingSingingKey => write!(f, "Keypair cannot be used to sign as its missing it's secret key component"),
            SelfError::KeyPairSignWrongKeypairType => write!(f, "Keypair cannot be used to sign messages"),
            SelfError::MessageContentMissing => write!(f, "Message is missing content field"),
            SelfError::MessageCTIMissing => write!(f, "Message is missing cti field"),
            SelfError::MessageDecodingInvalid => write!(f, "Message could not be decoded from invalid cbor"),
            SelfError::MessageEncodingInvalid => write!(f, "Message could not be encoded to valid cbor"),
            SelfError::MessageNoPayload => write!(f, "Message has no payload"),
            SelfError::MessageNoProtected => write!(f, "Message has no protected header"),
            SelfError::MessageNoSignature => write!(f, "Message has no signature"),
            SelfError::MessagePayloadInvalid => write!(f, "Message payload is not a map"),
            SelfError::MessageSignatureEncodingInvalid => write!(f, "Message signature is not valid base64"),
            SelfError::MessageSignatureInvalid => write!(f, "Message signature invalid"),
            SelfError::MessageSignatureKeypairMismatch => write!(f, "Message signature was not signed with the provided key"),
            SelfError::MessageSigningKeyInvalid => write!(f, "Message can only be signed with an ed25519 keypair"),
            SelfError::MessageUnsupportedSignatureAlgorithm => write!(f, "Message signature algorithm not supported"),
            SelfError::MessagingDestinationUnknown => write!(f, "Messaging destination or recipient unknown"),
            SelfError::MessagingGroupUnknown => write!(f, "Messaging group not found"),
            SelfError::RestRequestConnectionFailed => write!(f, "HTTP request connection failed"),
            SelfError::RestRequestConnectionTimeout => write!(f, "HTTP request connection timeout"),
            SelfError::RestRequestInvalid => write!(f, "HTTP request invalid"),
            SelfError::RestRequestRedirected => write!(f, "HTTP request was redirected too many times"),
            SelfError::RestRequestUnknown => write!(f, "HTTP request failed with unknown error"),
            SelfError::RestRequestURLInvalid => write!(f, "HTTP request URL is invalid"),
            SelfError::RestResponseBadRequest => write!(f, "HTTP response bad request"),
            SelfError::RestResposeBodyInvalid => write!(f, "HTTP response body encoding invalid"),
            SelfError::RestResponseConflict => write!(f, "HTTP response conflict"),
            SelfError::RestResponseNotFound => write!(f, "HTTP response not found"),
            SelfError::RestResponseUnauthorized => write!(f, "HTTP response unauthorized"),
            SelfError::RestResponseUnexpected => write!(f, "HTTP reponse status was unexpected"),
            SelfError::RpcConnectionFailed => write!(f, "Rpc connection failed"),
            SelfError::RpcConnectionTimeout => write!(f, "Rpc connection timeout"),
            SelfError::RpcBadGateway => write!(f, "Rpc bad gateway"),
            SelfError::RpcBadRequest => write!(f, "Rpc bad request"),
            SelfError::RpcConflict => write!(f, "Rpc conflict"),
            SelfError::RpcExpectationFailed => write!(f, "Rpc expectation failed"),
            SelfError::RpcForbidden => write!(f, "Rpc forbidden"),
            SelfError::RpcGatewayTimeout => write!(f, "Rpc gateway timeout"),
            SelfError::RpcGone => write!(f, "Rpc gone"),
            SelfError::RpcInternalServerError => write!(f, "Rpc internal server error"),
            SelfError::RpcLengthRequired => write!(f, "Rpc length required"),
            SelfError::RpcMethodNotAllowed => write!(f, "Rpc method not allowed"),
            SelfError::RpcNotAcceptable => write!(f, "Rpc not acceptable"),
            SelfError::RpcNotFound => write!(f, "Rpc not found"),
            SelfError::RpcNotImplemented => write!(f, "Rpc not implemented"),
            SelfError::RpcPaymentRequired => write!(f, "Rpc payment required"),
            SelfError::RpcPreconditionFailed => write!(f, "Rpc precondition failed"),
            SelfError::RpcRequestEntityTooLarge => write!(f, "Rpc request entity too large"),
            SelfError::RpcRequestFailed => write!(f, "Rpc request failed"),
            SelfError::RpcRequestTimeout => write!(f, "Rpc request timeout"),
            SelfError::RpcServiceUnavailable => write!(f, "Rpc service unavailable"),
            SelfError::RpcUnauthorized => write!(f, "Rpc unauthorized"),
            SelfError::RpcUnknown => write!(f, "Rpc unknown error"),
            SelfError::StorageColumnTypeMismatch => write!(f, "Storage column type mismatch"),
            SelfError::StorageConnectionFailed => write!(f, "Storage connection failed"),
            SelfError::StorageSessionNotFound => write!(f, "Session not found"),
            SelfError::StorageTableCreationFailed => write!(f, "Storage table creation failed"),
            SelfError::StorageTextUtf8Invalid => write!(f, "Storage row text is invalid utf-8"),
            SelfError::StorageTransactionCommitFailed => write!(f, "Storage transaction commit failed"),
            SelfError::StorageTransactionCreationFailed => write!(f, "Storage transaction creation failed"),
            SelfError::StorageTransactionRollbackFailed => write!(f, "Storage transaction rollback failed"),
            SelfError::StorageUnknown => write!(f, "Storage unknown error"),
            SelfError::TokenEncodingInvalid => write!(f, "Token could not be encoded"),
            SelfError::TokenSignatureInvalid => write!(f, "Token signature invalid"),
            SelfError::TokenTypeInvalid => write!(f, "Token type invalid or unsupported"),
            SelfError::TokenVersionInvalid => write!(f, "Token version not supported"),
            SelfError::WebsocketProtocolEmptyContent => write!(f, "Websocket protocol event had no content"),
            SelfError::WebsocketProtocolEncodingInvalid => write!(f, "Websocket protocol event could not be decoded"),
            SelfError::WebsocketProtocolErrorUnknown => write!(f, "Websocket protocol error code is unknown"),
            SelfError::WebsocketProtocolRecipientInvalid => write!(f, "Websocket protocol message recipient invalid"),
            SelfError::WebsocketProtocolSenderInvalid => write!(f, "Websocket protocol message sender invalid"),
            SelfError::WebsocketSenderIdentifierNotOwned => write!(f, "Websocket cannot send from an identifier that does not belong to this account"),
            SelfError::WebsocketTokenUnsupported => write!(f, "Websocket send attempted with an unsupported token"),
        }
    }
}
