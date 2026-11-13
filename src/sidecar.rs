//! Authenticated owner-side local IPC boundary.
//!
//! The sidecar accepts only `request` and `status`; approval and viewer-open
//! are intentionally absent from the wire protocol.  Client identity is
//! authenticated by an OS peer PID plus a custody-provided keyed challenge,
//! not by caller-supplied principal/PID fields.  Unknown clients, PID/path
//! mismatches, tenant mismatches, and failed authentication all fail closed.
//! A compromised same-user process can still defeat local controls; ADR-0005
//! explicitly keeps that residual limitation outside the proven boundary.

use async_trait::async_trait;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use zeroize::Zeroizing;

use crate::disclosure::{DisclosureScope, HumanDisclosure, RequesterRef, VaultBinding};

#[async_trait]
pub trait OpaqueDisclosureGateway: Send + Sync {
    async fn request(
        &self,
        principal_id: &str,
        tenant_id: &str,
        scope: DisclosureScope,
        binding: VaultBinding,
    ) -> Result<crate::disclosure::RequestResult, SidecarError>;
    async fn status(
        &self,
        principal_id: &str,
        tenant_id: &str,
        handle: &str,
    ) -> Result<crate::disclosure::StatusView, SidecarError>;
}

#[derive(Debug, Clone)]
pub enum SidecarEndpoint {
    #[cfg(unix)]
    Unix(PathBuf),
    #[cfg(windows)]
    WindowsNamedPipe(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    pub protocol: u16,
    pub client_id: String,
    pub pid: u32,
    pub executable_digest: String,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServerChallenge {
    nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientProof {
    pub tag: String,
}

/// Caller-visible sidecar operations. There is deliberately no approve,
/// cancel, deny, open-viewer, or raw-content variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum SidecarRequest {
    Request {
        scope: DisclosureScope,
        tenant_id: String,
        binding: VaultBinding,
    },
    Status {
        handle: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SidecarResponse {
    Request(crate::disclosure::RequestResult),
    Status(crate::disclosure::StatusView),
    Error { code: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedClient {
    pub client_id: String,
    pub principal_id: String,
    pub tenant_id: String,
    pub pid: u32,
    pub executable_digest: String,
}

/// Credential material is injected from protected OS custody. It is never
/// serialized, logged, or accepted from the wire.
#[derive(Clone)]
pub struct ClientCredential {
    pub client_id: String,
    pub principal_id: String,
    pub tenant_id: String,
    pub pid: u32,
    pub executable_digest: String,
    #[cfg(windows)]
    /// Canonical binary SID rendered as lowercase hex; populated from the
    /// authenticated process token, never from a wire hello.
    pub os_sid: String,
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for ClientCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("ClientCredential");
        debug.field("client_id", &self.client_id);
        debug.field("principal_id", &self.principal_id);
        debug.field("tenant_id", &self.tenant_id);
        debug.field("pid", &self.pid);
        debug.field("executable_digest", &self.executable_digest);
        #[cfg(windows)]
        debug.field("os_sid", &self.os_sid);
        debug.field("key", &"[REDACTED]").finish()
    }
}

impl ClientCredential {
    pub fn new(
        client_id: String,
        principal_id: String,
        tenant_id: String,
        pid: u32,
        executable_digest: String,
        key: [u8; 32],
    ) -> Self {
        Self {
            client_id,
            principal_id,
            tenant_id,
            pid,
            executable_digest,
            #[cfg(windows)]
            os_sid: String::new(),
            key: Zeroizing::new(key),
        }
    }

    #[cfg(windows)]
    pub fn for_windows(
        client_id: String,
        principal_id: String,
        tenant_id: String,
        pid: u32,
        executable_digest: String,
        os_sid: String,
        key: [u8; 32],
    ) -> Self {
        Self {
            client_id,
            principal_id,
            tenant_id,
            pid,
            executable_digest,
            os_sid,
            key: Zeroizing::new(key),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIdentity {
    pub pid: u32,
    pub uid: Option<u32>,
    #[cfg(windows)]
    pub sid: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum SidecarAuthError {
    #[error("client authentication failed")]
    Rejected,
    #[error("peer identity unavailable")]
    PeerUnavailable,
}

#[derive(Clone)]
pub struct HmacClientAuthenticator {
    clients: Arc<HashMap<String, ClientCredential>>,
    owner_uid: Option<u32>,
}

impl HmacClientAuthenticator {
    pub fn new(
        clients: impl IntoIterator<Item = ClientCredential>,
        owner_uid: Option<u32>,
    ) -> Self {
        Self {
            clients: Arc::new(
                clients
                    .into_iter()
                    .map(|c| (c.client_id.clone(), c))
                    .collect(),
            ),
            owner_uid,
        }
    }

    fn tag(key: &[u8; 32], hello: &ClientHello, challenge: &ServerChallenge) -> String {
        let canonical =
            serde_json::to_vec(&(hello, challenge)).expect("sidecar handshake serializes");
        blake3::keyed_hash(key, &canonical).to_hex().to_string()
    }

    pub fn expected_proof(
        &self,
        hello: &ClientHello,
        challenge: &str,
    ) -> Result<ClientProof, SidecarAuthError> {
        let client = self
            .clients
            .get(&hello.client_id)
            .ok_or(SidecarAuthError::Rejected)?;
        Ok(ClientProof {
            tag: Self::tag(
                &client.key,
                hello,
                &ServerChallenge {
                    nonce: challenge.into(),
                },
            ),
        })
    }

    fn authenticate(
        &self,
        hello: &ClientHello,
        challenge: &ServerChallenge,
        proof: &ClientProof,
        peer: PeerIdentity,
    ) -> Result<AuthenticatedClient, SidecarAuthError> {
        let client = self
            .clients
            .get(&hello.client_id)
            .ok_or(SidecarAuthError::Rejected)?;
        if hello.protocol != 1
            || hello.nonce.is_empty()
            || hello.pid != client.pid
            || hello.executable_digest != client.executable_digest
            || peer.pid != client.pid
            || self.owner_uid.is_some_and(|uid| peer.uid != Some(uid))
            || !peer_matches_os_identity(client, peer)
            || !constant_time_equal(
                proof.tag.as_bytes(),
                Self::tag(&client.key, hello, challenge).as_bytes(),
            )
        {
            return Err(SidecarAuthError::Rejected);
        }
        Ok(AuthenticatedClient {
            client_id: client.client_id.clone(),
            principal_id: client.principal_id.clone(),
            tenant_id: client.tenant_id.clone(),
            pid: client.pid,
            executable_digest: client.executable_digest.clone(),
        })
    }
}

#[cfg(windows)]
fn peer_matches_os_identity(client: &ClientCredential, peer: PeerIdentity) -> bool {
    !client.os_sid.is_empty() && peer.sid.as_deref() == Some(client.os_sid.as_str())
}

#[cfg(not(windows))]
fn peer_matches_os_identity(_: &ClientCredential, _: PeerIdentity) -> bool {
    true
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[derive(Debug, thiserror::Error)]
pub enum SidecarError {
    #[error("sidecar endpoint unavailable")]
    Unavailable,
    #[error("sidecar protocol rejected")]
    Protocol,
    #[error("sidecar authentication failed")]
    Authentication,
    #[error("sidecar operation denied")]
    Denied,
    #[error("sidecar I/O failed")]
    Io,
}

#[derive(Clone)]
pub struct LocalSidecar {
    engine: Arc<HumanDisclosure>,
    endpoint: SidecarEndpoint,
    authenticator: HmacClientAuthenticator,
}

/// Authenticated client for the local sidecar.  This is the only supported
/// MCP-facing adapter: it can request and poll opaque state, but has no
/// methods for approval, viewer opening, or raw-content transfer.
pub struct LocalSidecarClient {
    credential: ClientCredential,
    #[cfg(unix)]
    read: tokio::sync::Mutex<BufReader<tokio::io::ReadHalf<tokio::net::UnixStream>>>,
    #[cfg(unix)]
    write: tokio::sync::Mutex<tokio::io::WriteHalf<tokio::net::UnixStream>>,
    #[cfg(windows)]
    read: tokio::sync::Mutex<
        BufReader<tokio::io::ReadHalf<tokio::net::windows::named_pipe::NamedPipeClient>>,
    >,
    #[cfg(windows)]
    write:
        tokio::sync::Mutex<tokio::io::WriteHalf<tokio::net::windows::named_pipe::NamedPipeClient>>,
}

impl std::fmt::Debug for LocalSidecarClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalSidecarClient")
            .field("client_id", &self.credential.client_id)
            .field("principal_id", &self.credential.principal_id)
            .field("tenant_id", &self.credential.tenant_id)
            .field("pid", &self.credential.pid)
            .finish()
    }
}

impl LocalSidecarClient {
    pub async fn connect(
        endpoint: &SidecarEndpoint,
        credential: ClientCredential,
    ) -> Result<Self, SidecarError> {
        #[cfg(unix)]
        if let SidecarEndpoint::Unix(path) = endpoint {
            let stream = tokio::net::UnixStream::connect(path)
                .await
                .map_err(|_| SidecarError::Unavailable)?;
            let (read, write) = tokio::io::split(stream);
            let mut read = BufReader::new(read);
            let mut write = write;
            client_handshake(&mut read, &mut write, &credential).await?;
            return Ok(Self {
                credential,
                read: tokio::sync::Mutex::new(read),
                write: tokio::sync::Mutex::new(write),
            });
        }
        #[cfg(windows)]
        if let SidecarEndpoint::WindowsNamedPipe(name) = endpoint {
            use tokio::net::windows::named_pipe::ClientOptions;
            let stream = ClientOptions::new()
                .open(name)
                .map_err(|_| SidecarError::Unavailable)?;
            let (read, write) = tokio::io::split(stream);
            let mut read = BufReader::new(read);
            let mut write = write;
            client_handshake(&mut read, &mut write, &credential).await?;
            return Ok(Self {
                credential,
                read: tokio::sync::Mutex::new(read),
                write: tokio::sync::Mutex::new(write),
            });
        }
        Err(SidecarError::Unavailable)
    }

    async fn send(&self, request: &SidecarRequest) -> Result<SidecarResponse, SidecarError> {
        let mut read = self.read.lock().await;
        let mut write = self.write.lock().await;
        write_json(&mut *write, request).await?;
        let mut line = String::new();
        if read
            .read_line(&mut line)
            .await
            .map_err(|_| SidecarError::Io)?
            == 0
        {
            return Err(SidecarError::Protocol);
        }
        serde_json::from_str::<SidecarResponse>(&line).map_err(|_| SidecarError::Protocol)
    }
}

async fn client_handshake<R, W>(
    read: &mut BufReader<R>,
    write: &mut W,
    credential: &ClientCredential,
) -> Result<(), SidecarError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut nonce);
    let hello = ClientHello {
        protocol: 1,
        client_id: credential.client_id.clone(),
        pid: credential.pid,
        executable_digest: credential.executable_digest.clone(),
        nonce: nonce.iter().map(|b| format!("{b:02x}")).collect(),
    };
    write_json(write, &hello).await?;
    let mut line = String::new();
    if read
        .read_line(&mut line)
        .await
        .map_err(|_| SidecarError::Io)?
        == 0
    {
        return Err(SidecarError::Protocol);
    }
    let challenge: ServerChallenge =
        serde_json::from_str(&line).map_err(|_| SidecarError::Protocol)?;
    let proof = HmacClientAuthenticator::new([credential.clone()], None)
        .expected_proof(&hello, &challenge.nonce)
        .map_err(|_| SidecarError::Authentication)?;
    write_json(write, &proof).await?;
    Ok(())
}

#[async_trait]
impl OpaqueDisclosureGateway for LocalSidecarClient {
    async fn request(
        &self,
        principal_id: &str,
        tenant_id: &str,
        scope: DisclosureScope,
        binding: VaultBinding,
    ) -> Result<crate::disclosure::RequestResult, SidecarError> {
        if principal_id != self.credential.principal_id || tenant_id != self.credential.tenant_id {
            return Err(SidecarError::Denied);
        }
        match self
            .send(&SidecarRequest::Request {
                scope,
                tenant_id: tenant_id.to_owned(),
                binding,
            })
            .await?
        {
            SidecarResponse::Request(result) => Ok(result),
            SidecarResponse::Error { .. } | SidecarResponse::Status(_) => Err(SidecarError::Denied),
        }
    }

    async fn status(
        &self,
        principal_id: &str,
        tenant_id: &str,
        handle: &str,
    ) -> Result<crate::disclosure::StatusView, SidecarError> {
        if principal_id != self.credential.principal_id || tenant_id != self.credential.tenant_id {
            return Err(SidecarError::Denied);
        }
        match self
            .send(&SidecarRequest::Status {
                handle: handle.to_owned(),
            })
            .await?
        {
            SidecarResponse::Status(result) => Ok(result),
            SidecarResponse::Error { .. } | SidecarResponse::Request(_) => {
                Err(SidecarError::Denied)
            }
        }
    }
}

impl LocalSidecar {
    pub fn new(
        engine: Arc<HumanDisclosure>,
        endpoint: SidecarEndpoint,
        authenticator: HmacClientAuthenticator,
    ) -> Self {
        Self {
            engine,
            endpoint,
            authenticator,
        }
    }

    /// Bind and serve the owner-controlled local endpoint. The socket/pipe is
    /// not HTTP and cannot return raw content; every connection authenticates
    /// its OS peer before reading a request.
    pub async fn serve(self) -> Result<(), SidecarError> {
        #[cfg(unix)]
        {
            use tokio::net::UnixListener;
            let SidecarEndpoint::Unix(path) = &self.endpoint;
            let _ = std::fs::remove_file(path);
            let listener = UnixListener::bind(path).map_err(|_| SidecarError::Unavailable)?;
            // The socket is an owner-controlled endpoint.  Refuse a broad
            // filesystem ACL even though peer credentials authenticate each
            // connection, so untrusted same-host users cannot probe it.
            std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
                .map_err(|_| SidecarError::Unavailable)?;
            loop {
                let (stream, _) = listener.accept().await.map_err(|_| SidecarError::Io)?;
                let credentials = stream
                    .peer_cred()
                    .map_err(|_| SidecarError::Authentication)?;
                let peer = PeerIdentity {
                    pid: u32::try_from(credentials.pid().ok_or(SidecarError::Authentication)?)
                        .map_err(|_| SidecarError::Authentication)?,
                    uid: Some(credentials.uid()),
                    #[cfg(windows)]
                    sid: None,
                };
                let engine = self.engine.clone();
                let auth = self.authenticator.clone();
                tokio::spawn(async move {
                    let _ = serve_connection(stream, peer, engine, auth).await;
                });
            }
        }
        #[cfg(windows)]
        {
            use tokio::net::windows::named_pipe::ServerOptions;
            let SidecarEndpoint::WindowsNamedPipe(name) = &self.endpoint;
            loop {
                let server = ServerOptions::new()
                    .first_pipe_instance(true)
                    .create(name)
                    .map_err(|_| SidecarError::Unavailable)?;
                restrict_windows_pipe_acl(&server)?;
                server.connect().await.map_err(|_| SidecarError::Io)?;
                let peer = windows_pipe_peer(&server).ok_or(SidecarError::Authentication)?;
                let engine = self.engine.clone();
                let auth = self.authenticator.clone();
                tokio::spawn(async move {
                    let _ = serve_connection(server, peer, engine, auth).await;
                });
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(SidecarError::Unavailable)
        }
    }
}

#[cfg(windows)]
fn restrict_windows_pipe_acl(
    server: &tokio::net::windows::named_pipe::NamedPipeServer,
) -> Result<(), SidecarError> {
    use std::os::windows::io::AsRawHandle;
    use windows::{
        Win32::{
            Foundation::{HANDLE, HLOCAL, LocalFree},
            Security::Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            Security::{DACL_SECURITY_INFORMATION, SetKernelObjectSecurity},
        },
        core::{HSTRING, PCWSTR},
    };
    // OW is the owner of the named-pipe object, i.e. the account running the
    // sidecar. No broad Users/Everyone ACE is admitted.
    let sddl = HSTRING::from("D:(A;;GA;;;OW)");
    let mut descriptor = windows::Win32::Security::PSECURITY_DESCRIPTOR::default();
    // SAFETY: sddl is a live NUL-terminated string and descriptor is a valid
    // out-pointer. The descriptor is released with LocalFree below.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
        .map_err(|_| SidecarError::Unavailable)?;
    }
    // SAFETY: the pipe handle is live and descriptor is the valid ACL returned
    // by the conversion call; both calls are synchronous.
    let result = unsafe {
        SetKernelObjectSecurity(
            HANDLE(server.as_raw_handle() as isize),
            DACL_SECURITY_INFORMATION,
            descriptor,
        )
    }
    .map_err(|_| SidecarError::Unavailable);
    // SAFETY: descriptor is the one allocation returned by the conversion API.
    unsafe {
        let _ = LocalFree(HLOCAL(descriptor.0 as isize));
    }
    result
}

async fn write_json<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> Result<(), SidecarError> {
    let line = serde_json::to_vec(value).map_err(|_| SidecarError::Protocol)?;
    writer
        .write_all(&line)
        .await
        .map_err(|_| SidecarError::Io)?;
    writer.write_all(b"\n").await.map_err(|_| SidecarError::Io)
}

async fn serve_connection<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    peer: PeerIdentity,
    engine: Arc<HumanDisclosure>,
    auth: HmacClientAuthenticator,
) -> Result<(), SidecarError> {
    let (read, mut write) = tokio::io::split(stream);
    let mut lines = BufReader::new(read).lines();
    let hello: ClientHello = serde_json::from_str(
        &lines
            .next_line()
            .await
            .map_err(|_| SidecarError::Protocol)?
            .ok_or(SidecarError::Protocol)?,
    )
    .map_err(|_| SidecarError::Protocol)?;
    let mut nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut nonce);
    let challenge = ServerChallenge {
        nonce: nonce.iter().map(|b| format!("{b:02x}")).collect(),
    };
    write_json(&mut write, &challenge).await?;
    let proof: ClientProof = serde_json::from_str(
        &lines
            .next_line()
            .await
            .map_err(|_| SidecarError::Protocol)?
            .ok_or(SidecarError::Protocol)?,
    )
    .map_err(|_| SidecarError::Protocol)?;
    let client = match auth.authenticate(&hello, &challenge, &proof, peer) {
        Ok(c) => c,
        Err(_) => {
            let _ = write_json(
                &mut write,
                &SidecarResponse::Error {
                    code: "client_unauthorized".into(),
                },
            )
            .await;
            return Err(SidecarError::Authentication);
        }
    };
    while let Some(line) = lines
        .next_line()
        .await
        .map_err(|_| SidecarError::Protocol)?
    {
        let request: SidecarRequest =
            serde_json::from_str(&line).map_err(|_| SidecarError::Protocol)?;
        let response = match request {
            SidecarRequest::Request {
                scope,
                tenant_id,
                binding,
            } => {
                if tenant_id != client.tenant_id {
                    SidecarResponse::Error {
                        code: "tenant_unauthorized".into(),
                    }
                } else {
                    match engine
                        .request(
                            scope,
                            RequesterRef {
                                principal_id: client.principal_id.clone(),
                                tenant_id: client.tenant_id.clone(),
                            },
                            binding,
                        )
                        .await
                    {
                        Ok(result) => SidecarResponse::Request(result),
                        Err(_) => SidecarResponse::Error {
                            code: "request_denied".into(),
                        },
                    }
                }
            }
            SidecarRequest::Status { handle } => match engine
                .status_for(&handle, &client.principal_id, &client.tenant_id)
                .await
            {
                Ok(status) => SidecarResponse::Status(status),
                Err(_) => SidecarResponse::Error {
                    code: "status_unavailable".into(),
                },
            },
        };
        write_json(&mut write, &response).await?;
    }
    Ok(())
}

#[cfg(windows)]
fn windows_pipe_peer(
    server: &tokio::net::windows::named_pipe::NamedPipeServer,
) -> Option<PeerIdentity> {
    use std::os::windows::io::AsRawHandle;
    use windows::{Win32::Foundation::HANDLE, Win32::System::Pipes::GetNamedPipeClientProcessId};
    let mut pid = 0u32;
    // SAFETY: the handle belongs to the connected NamedPipeServer and the PID
    // output points to valid writable storage for this synchronous call.
    unsafe {
        GetNamedPipeClientProcessId(HANDLE(server.as_raw_handle() as isize), &mut pid).ok()?;
    }
    let sid = windows_pipe_client_sid(pid)?;
    Some(PeerIdentity {
        pid,
        uid: None,
        sid: Some(sid),
    })
}

#[cfg(windows)]
fn windows_pipe_client_sid(pid: u32) -> Option<String> {
    use std::{mem::size_of, slice};
    use windows::Win32::{
        Foundation::CloseHandle,
        Security::{
            GetLengthSid, GetTokenInformation, OpenProcessToken, TOKEN_QUERY, TOKEN_USER, TokenUser,
        },
        System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
    };
    let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
    let mut token = Default::default();
    // SAFETY: process is a live handle returned by OpenProcess and token is a
    // valid out-pointer for this synchronous API.
    let opened = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.is_ok();
    if !opened {
        // SAFETY: process is the handle acquired above and has not been closed.
        unsafe { CloseHandle(process).ok()? };
        return None;
    }
    let mut needed = 0u32;
    // SAFETY: the sizing call intentionally supplies a null buffer and a valid
    // size out-pointer, as required by GetTokenInformation.
    unsafe {
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
    }
    if needed < size_of::<TOKEN_USER>() as u32 {
        // SAFETY: both handles were successfully acquired and are closed once.
        unsafe {
            CloseHandle(token).ok()?;
            CloseHandle(process).ok()?;
        }
        return None;
    }
    let mut bytes = vec![0u8; needed as usize];
    // SAFETY: bytes has the size returned by the sizing call and remains live
    // while Windows writes the TOKEN_USER structure into it.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(bytes.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
        .is_ok()
    };
    if !ok {
        // SAFETY: both handles were successfully acquired and are closed once.
        unsafe {
            CloseHandle(token).ok()?;
            CloseHandle(process).ok()?;
        }
        return None;
    }
    // SAFETY: GetTokenInformation succeeded and bytes contains a valid
    // TOKEN_USER whose SID remains valid for the lifetime of bytes.
    let user = unsafe { &*(bytes.as_ptr() as *const TOKEN_USER) };
    let length = unsafe { GetLengthSid(user.User.Sid) } as usize;
    let sid = unsafe { slice::from_raw_parts(user.User.Sid.0 as *const u8, length) };
    let rendered = sid.iter().map(|b| format!("{b:02x}")).collect::<String>();
    // SAFETY: both handles were successfully acquired and are closed once.
    unsafe {
        CloseHandle(token).ok()?;
        CloseHandle(process).ok()?;
    }
    Some(rendered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spoofed_pid_or_digest_is_rejected() {
        let auth = HmacClientAuthenticator::new(
            [ClientCredential::new(
                "mcp".into(),
                "agent".into(),
                "tenant".into(),
                42,
                "digest".into(),
                [9; 32],
            )],
            Some(7),
        );
        let hello = ClientHello {
            protocol: 1,
            client_id: "mcp".into(),
            pid: 42,
            executable_digest: "digest".into(),
            nonce: "client".into(),
        };
        let proof = auth.expected_proof(&hello, "server").unwrap();
        assert!(
            auth.authenticate(
                &hello,
                &ServerChallenge {
                    nonce: "server".into()
                },
                &proof,
                PeerIdentity {
                    pid: 43,
                    uid: Some(7),
                    #[cfg(windows)]
                    sid: Some("sid".into()),
                }
            )
            .is_err()
        );
        assert!(
            auth.authenticate(
                &hello,
                &ServerChallenge {
                    nonce: "server".into()
                },
                &proof,
                PeerIdentity {
                    pid: 42,
                    uid: Some(8),
                    #[cfg(windows)]
                    sid: Some("sid".into()),
                }
            )
            .is_err()
        );
    }

    #[test]
    fn wire_contract_is_opaque_only() {
        let request = serde_json::to_string(&SidecarRequest::Status {
            handle: "opaque-handle".into(),
        })
        .unwrap();
        assert!(!request.contains("approve"));
        assert!(!request.contains("open_viewer"));
        assert!(!request.contains("raw"));
        let response = serde_json::to_string(&SidecarResponse::Error {
            code: "request_denied".into(),
        })
        .unwrap();
        assert!(!response.contains("content"));
        assert!(!response.contains("value"));
    }
}
