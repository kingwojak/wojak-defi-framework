use std::collections::{HashMap, VecDeque};
use std::io;

use async_trait::async_trait;
use futures::channel::{mpsc, oneshot};
use futures::io::{AsyncRead, AsyncWrite};
use futures_ticker::Ticker;
use instant::{Duration, Instant};
use libp2p::core::upgrade::{read_length_prefixed, write_length_prefixed};
use libp2p::{request_response::{Behaviour as RequestResponse, RequestId, ResponseChannel},
             swarm::NetworkBehaviour,
             PeerId};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{decode_message, encode_message};

const MAX_BUFFER_SIZE: usize = 1024 * 1024 - 100;

macro_rules! try_io {
    ($e: expr) => {
        match $e {
            Ok(ok) => ok,
            Err(err) => return Err(io::Error::new(io::ErrorKind::InvalidData, err)),
        }
    };
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PeerRequest {
    pub req: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum PeerResponse {
    Ok { res: Vec<u8> },
    None,
    Err { err: String },
}

pub type RequestResponseReceiver = mpsc::UnboundedReceiver<(PeerId, PeerRequest, oneshot::Sender<PeerResponse>)>;
pub type RequestResponseSender = mpsc::UnboundedSender<(PeerId, PeerRequest, oneshot::Sender<PeerResponse>)>;

pub enum RequestResponseBehaviourEvent {
    InboundRequest {
        peer_id: PeerId,
        request: PeerRequest,
        response_channel: ResponseChannel<PeerResponse>,
    },
}

struct PendingRequest {
    tx: oneshot::Sender<PeerResponse>,
    initiated_at: Instant,
}

#[derive(Debug)]
pub struct AdexResponseChannel(ResponseChannel<PeerResponse>);

impl From<ResponseChannel<PeerResponse>> for AdexResponseChannel {
    fn from(res: ResponseChannel<PeerResponse>) -> Self { AdexResponseChannel(res) }
}

impl From<AdexResponseChannel> for ResponseChannel<PeerResponse> {
    fn from(res: AdexResponseChannel) -> Self { res.0 }
}

#[derive(Debug, Clone)]
pub enum Protocol {
    Version1,
}

impl AsRef<str> for Protocol {
    fn as_ref(&self) -> &str {
        match self {
            Protocol::Version1 => "/request-response/1",
        }
    }
}

#[derive(Clone)]
pub struct Codec<Proto, Req, Res> {
    phantom: std::marker::PhantomData<(Proto, Req, Res)>,
}

impl<Proto, Req, Res> Default for Codec<Proto, Req, Res> {
    fn default() -> Self {
        Codec {
            phantom: Default::default(),
        }
    }
}

#[async_trait]
impl<
        Proto: Clone + AsRef<str> + Send + Sync,
        Req: DeserializeOwned + Serialize + Send + Sync,
        Res: DeserializeOwned + Serialize + Send + Sync,
    > libp2p::request_response::Codec for Codec<Proto, Req, Res>
{
    type Protocol = Proto;
    type Request = Req;
    type Response = Res;

    async fn read_request<T>(&mut self, _protocol: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_to_end(io).await
    }

    async fn read_response<T>(&mut self, _protocol: &Self::Protocol, io: &mut T) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_to_end(io).await
    }

    async fn write_request<T>(&mut self, _protocol: &Self::Protocol, io: &mut T, req: Self::Request) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_all(io, &req).await
    }

    async fn write_response<T>(&mut self, _protocol: &Self::Protocol, io: &mut T, res: Self::Response) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_all(io, &res).await
    }
}

async fn read_to_end<T, M>(io: &mut T) -> io::Result<M>
where
    T: AsyncRead + Unpin + Send,
    M: DeserializeOwned,
{
    match read_length_prefixed(io, MAX_BUFFER_SIZE).await {
        Ok(data) => Ok(try_io!(decode_message(&data))),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
    }
}

async fn write_all<T, M>(io: &mut T, msg: &M) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
    M: Serialize,
{
    let data = try_io!(encode_message(msg));
    if data.len() > MAX_BUFFER_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Try to send data size over maximum",
        ));
    }
    write_length_prefixed(io, data).await
}

pub struct RequestResponseBehaviour {
    /// The inner RequestResponse network behaviour.
    inner: RequestResponse<Codec<Protocol, PeerRequest, PeerResponse>>,
    rx: RequestResponseReceiver,
    tx: RequestResponseSender,
    pending_requests: HashMap<RequestId, PendingRequest>,
    /// Events that need to be yielded to the outside when polling.
    events: VecDeque<RequestResponseBehaviourEvent>,
    /// Timeout for pending requests
    timeout: Duration,
    /// Interval for request timeout check
    timeout_interval: Ticker,
}

impl NetworkBehaviour for RequestResponseBehaviour {
    type ConnectionHandler =
        <RequestResponse<Codec<Protocol, PeerRequest, PeerResponse>> as NetworkBehaviour>::ConnectionHandler;

    type ToSwarm = RequestResponseBehaviourEvent;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: libp2p::swarm::ConnectionId,
        peer: PeerId,
        local_addr: &libp2p::Multiaddr,
        remote_addr: &libp2p::Multiaddr,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        todo!()
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: libp2p::swarm::ConnectionId,
        peer: PeerId,
        addr: &libp2p::Multiaddr,
        role_override: libp2p::core::Endpoint,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        todo!()
    }

    fn on_swarm_event(&mut self, event: libp2p::swarm::FromSwarm<Self::ConnectionHandler>) { todo!() }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: libp2p::swarm::ConnectionId,
        _event: libp2p::swarm::THandlerOutEvent<Self>,
    ) {
        todo!()
    }

    fn poll(
        &mut self,
        cx: &mut std::task::Context<'_>,
        params: &mut impl libp2p::swarm::PollParameters,
    ) -> std::task::Poll<libp2p::swarm::ToSwarm<Self::ToSwarm, libp2p::swarm::THandlerInEvent<Self>>> {
        todo!()
    }
}
