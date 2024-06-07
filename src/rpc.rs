use crate::crypto::pow::ProofOfWork;
use crate::datastore::Datastore;
use crate::hashgraph::Hashgraph;
use crate::protocol::rpc;
use crate::protocol::rpc::api_server::{Api, ApiServer};
use crate::protocol::rpc::{
    AcquireRequest, AcquireResponse, ExecuteRequest, ListRequest, ListResponse, PublishRequest,
    PurgeRequest, ResolveRequest, ResolveResponse,
};

use prost::Message;
use tokio::sync::Mutex;
use tonic::{transport::Server, Request, Response, Status};
use tracing_subscriber::filter;

use std::collections::VecDeque;
use std::sync::Arc;

pub fn test_api(
    runtime: &mut tokio::runtime::Runtime,
    port: u16,
    datastore: Arc<Mutex<Datastore>>,
) {
    runtime.spawn(async move {
        let addr = format!("127.0.0.1:{}", port).parse().expect("bad port");
        let handler = ApiHandler::new(datastore);

        Server::builder()
            .add_service(ApiServer::new(handler))
            .serve(addr)
            .await
            .expect("failed to start rpc service");
    });
}

pub struct ApiHandler {
    datastore: Arc<Mutex<Datastore>>,
}

impl ApiHandler {
    fn new(datastore: Arc<Mutex<Datastore>>) -> ApiHandler {
        ApiHandler { datastore }
    }
}

#[tonic::async_trait]
impl Api for ApiHandler {
    async fn resolve(
        &self,
        request: Request<rpc::Request>,
    ) -> Result<Response<rpc::Response>, Status> {
        let payload = request.into_inner();

        let resolve = match ResolveRequest::decode(payload.content.as_ref()) {
            Ok(resolve) => resolve,
            Err(_) => return Err(Status::unknown("bad request encoding")),
        };

        let datastore = self.datastore.lock().await;

        let log = match datastore.identities.get(&resolve.id) {
            Some(log) => log,
            None => return Err(Status::not_found("identity not found")),
        };

        let mut content = Vec::new();

        let mut filtered_log: Vec<Vec<u8>> = Vec::new();
        if log.len() > resolve.from as usize {
            filtered_log = log.clone().split_off(resolve.from as usize);
        }

        let encode_result = ResolveResponse { log: filtered_log }.encode(&mut content);

        if encode_result.is_err() {
            return Err(Status::internal("internal server error"));
        };

        let reply = rpc::Response {
            header: Some(rpc::ResponseHeader {
                version: rpc::Version::V1 as i32,
                status: rpc::ResponseStatus::StatusAccepted as i32,
                message: String::new(),
            }),
            content,
        };

        Ok(Response::new(reply))
    }

    async fn resolve_document(
        &self,
        _request: Request<rpc::Request>,
    ) -> Result<Response<rpc::Response>, Status> {
        let reply = rpc::Response {
            header: Some(rpc::ResponseHeader {
                version: rpc::Version::V1 as i32,
                status: rpc::ResponseStatus::StatusAccepted as i32,
                message: String::new(),
            }),
            content: vec![0; 0],
        };

        Ok(Response::new(reply))
    }

    async fn execute(
        &self,
        request: Request<rpc::Request>,
    ) -> Result<Response<rpc::Response>, Status> {
        let payload = request.into_inner();

        if let Some(pow) = payload.proof_of_work {
            if !ProofOfWork::new(8).validate(&payload.content, &pow.hash, pow.nonce) {
                return Err(Status::permission_denied("bad request pow - insufficient"));
            }
        } else {
            return Err(Status::permission_denied("bad request pow"));
        }

        let execute = match ExecuteRequest::decode(payload.content.as_ref()) {
            Ok(execute) => execute,
            Err(_) => return Err(Status::unknown("bad request encoding")),
        };

        let mut datastore = self.datastore.lock().await;
        let mut graph = Hashgraph::new();

        if let Some(history) = datastore.identities.get(&execute.id) {
            graph = match Hashgraph::load(history, false) {
                Ok(graph) => graph,
                Err(_) => return Err(Status::unknown("invalid hashgraph history")),
            };
        } else {
            datastore.identities.insert(execute.id.clone(), Vec::new());
        }

        if graph.execute(execute.operation.clone()).is_err() {
            return Err(Status::unknown("invalid hashgraph operation"));
        }

        if let Some(identity) = datastore.identities.get_mut(&execute.id) {
            identity.push(execute.operation);
        }

        let reply = rpc::Response {
            header: Some(rpc::ResponseHeader {
                version: rpc::Version::V1 as i32,
                status: rpc::ResponseStatus::StatusAccepted as i32,
                message: String::new(),
            }),
            content: vec![0; 0],
        };

        Ok(Response::new(reply))
    }

    async fn acquire(
        &self,
        request: Request<rpc::Request>,
    ) -> Result<Response<rpc::Response>, Status> {
        let payload = request.into_inner();

        if let Some(pow) = payload.proof_of_work {
            if !ProofOfWork::new(8).validate(&payload.content, &pow.hash, pow.nonce) {
                return Err(Status::permission_denied("bad request pow - insufficient"));
            }
        } else {
            return Err(Status::permission_denied("bad request pow"));
        }

        // TODO decode tokens and authorize...

        let acquire = match AcquireRequest::decode(payload.content.as_ref()) {
            Ok(acquire) => acquire,
            Err(_) => return Err(Status::unknown("bad request encoding")),
        };

        let mut datastore = self.datastore.lock().await;

        let key = match datastore.key_packages.get_mut(&acquire.id) {
            Some(queue) => match queue.pop_front() {
                Some(key) => key,
                None => return Err(Status::not_found("inbox not found")),
            },
            None => return Err(Status::not_found("inbox not found")),
        };

        let mut content = Vec::new();

        let encode_result = AcquireResponse { key }.encode(&mut content);

        if encode_result.is_err() {
            return Err(Status::internal("internal server error"));
        };

        let reply = rpc::Response {
            header: Some(rpc::ResponseHeader {
                version: rpc::Version::V1 as i32,
                status: rpc::ResponseStatus::StatusAccepted as i32,
                message: String::new(),
            }),
            content,
        };

        Ok(Response::new(reply))
    }

    async fn publish(
        &self,
        request: Request<rpc::Request>,
    ) -> Result<Response<rpc::Response>, Status> {
        let payload = request.into_inner();

        if let Some(pow) = payload.proof_of_work {
            if !ProofOfWork::new(8).validate(&payload.content, &pow.hash, pow.nonce) {
                return Err(Status::permission_denied("bad request pow - insufficient"));
            }
        } else {
            return Err(Status::permission_denied("bad request pow"));
        }

        let publish = match PublishRequest::decode(payload.content.as_ref()) {
            Ok(publish) => publish,
            Err(_) => return Err(Status::unknown("bad request encoding")),
        };

        let mut datastore = self.datastore.lock().await;

        let queue = match datastore.key_packages.get_mut(&publish.id) {
            Some(queue) => queue,
            None => {
                datastore
                    .key_packages
                    .insert(publish.id.clone(), VecDeque::new());
                datastore
                    .key_packages
                    .get_mut(&publish.id)
                    .expect("not empty")
            }
        };

        publish.keys.into_iter().for_each(|pk| queue.push_back(pk));

        let reply = rpc::Response {
            header: Some(rpc::ResponseHeader {
                version: rpc::Version::V1 as i32,
                status: rpc::ResponseStatus::StatusAccepted as i32,
                message: String::new(),
            }),
            content: Vec::new(),
        };

        Ok(Response::new(reply))
    }

    async fn list(
        &self,
        request: Request<rpc::Request>,
    ) -> Result<Response<rpc::Response>, Status> {
        let payload = request.into_inner();

        // TODO authenticate request

        let publish = match ListRequest::decode(payload.content.as_ref()) {
            Ok(publish) => publish,
            Err(_) => return Err(Status::unknown("bad request encoding")),
        };

        let mut datastore = self.datastore.lock().await;

        let keys: Vec<Vec<u8>> = match datastore.key_packages.get_mut(&publish.id) {
            Some(queue) => queue,
            None => {
                datastore
                    .key_packages
                    .insert(publish.id.clone(), VecDeque::new());
                datastore
                    .key_packages
                    .get_mut(&publish.id)
                    .expect("not empty")
            }
        }
        .iter()
        .cloned()
        .collect();

        let mut content = Vec::new();

        let encode_result = ListResponse { keys }.encode(&mut content);

        if encode_result.is_err() {
            return Err(Status::internal("internal server error"));
        };

        let reply = rpc::Response {
            header: Some(rpc::ResponseHeader {
                version: rpc::Version::V1 as i32,
                status: rpc::ResponseStatus::StatusAccepted as i32,
                message: String::new(),
            }),
            content,
        };

        Ok(Response::new(reply))
    }

    async fn purge(
        &self,
        request: Request<rpc::Request>,
    ) -> Result<Response<rpc::Response>, Status> {
        let payload = request.into_inner();

        // TODO authenticate request

        let publish = match PurgeRequest::decode(payload.content.as_ref()) {
            Ok(publish) => publish,
            Err(_) => return Err(Status::unknown("bad request encoding")),
        };

        let mut datastore = self.datastore.lock().await;

        match datastore.key_packages.get_mut(&publish.id) {
            Some(queue) => queue,
            None => {
                datastore
                    .key_packages
                    .insert(publish.id.clone(), VecDeque::new());
                datastore
                    .key_packages
                    .get_mut(&publish.id)
                    .expect("not empty")
            }
        }
        .clear();

        let reply = rpc::Response {
            header: Some(rpc::ResponseHeader {
                version: rpc::Version::V1 as i32,
                status: rpc::ResponseStatus::StatusAccepted as i32,
                message: String::new(),
            }),
            content: Vec::new(),
        };

        Ok(Response::new(reply))
    }

    async fn notify(
        &self,
        _request: Request<rpc::Request>,
    ) -> Result<Response<rpc::Response>, Status> {
        let reply = rpc::Response {
            header: Some(rpc::ResponseHeader {
                version: rpc::Version::V1 as i32,
                status: rpc::ResponseStatus::StatusAccepted as i32,
                message: String::new(),
            }),
            content: vec![0; 0],
        };

        Ok(Response::new(reply))
    }

    async fn challenge(
        &self,
        _request: Request<rpc::Request>,
    ) -> Result<Response<rpc::Response>, Status> {
        let reply = rpc::Response {
            header: Some(rpc::ResponseHeader {
                version: rpc::Version::V1 as i32,
                status: rpc::ResponseStatus::StatusAccepted as i32,
                message: String::new(),
            }),
            content: vec![0; 0],
        };

        Ok(Response::new(reply))
    }

    async fn verify_app_publisher(
        &self,
        _request: Request<rpc::Request>,
    ) -> Result<Response<rpc::Response>, Status> {
        let reply = rpc::Response {
            header: Some(rpc::ResponseHeader {
                version: rpc::Version::V1 as i32,
                status: rpc::ResponseStatus::StatusAccepted as i32,
                message: String::new(),
            }),
            content: vec![0; 0],
        };

        Ok(Response::new(reply))
    }
}
