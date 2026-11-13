//! Native owner-presence and viewer process boundary.
//!
//! Supported platforms are Windows (Windows Hello) and macOS (Keychain
//! `USER_PRESENCE`, which invokes LocalAuthentication).  Every other target
//! returns a fixed error.  The viewer child receives content through an
//! inherited stdin pipe only; content is never placed in argv, environment,
//! temporary files, logs, HTTP, or MCP.

use async_trait::async_trait;
use std::{collections::HashMap, path::PathBuf, process::Stdio, sync::Arc};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::disclosure::{
    DisclosureChallenge, OwnerAuthError, OwnerIdentity, OwnerPresence, SecureViewerSink,
    ViewerContent, ViewerError, ViewerSessionMeta,
};

const SERVICE: &str = "com.hacienda.owner-presence.v1";

#[derive(Debug, thiserror::Error)]
pub enum NativeViewerError {
    #[error("native viewer unsupported on this platform")]
    UnsupportedPlatform,
    #[error("native viewer executable unavailable")]
    Unavailable,
    #[error("native viewer process failed")]
    Failed,
}

/// Launches the installed Hacienda native viewer.  The executable path is
/// configuration, while the only argument is a constant subcommand.
#[derive(Clone, Debug)]
pub struct NativeViewerSink {
    executable: PathBuf,
}

impl NativeViewerSink {
    pub fn new(executable: PathBuf) -> Self {
        Self { executable }
    }
    pub fn current_executable() -> std::io::Result<PathBuf> {
        std::env::current_exe()
    }
}

#[async_trait]
impl SecureViewerSink for NativeViewerSink {
    async fn deliver(
        &self,
        _meta: &ViewerSessionMeta,
        content: ViewerContent,
    ) -> Result<(), ViewerError> {
        if !cfg!(any(target_os = "windows", target_os = "macos")) {
            return Err(ViewerError::Unavailable);
        }
        let mut child = Command::new(&self.executable);
        child
            .arg("native-viewer")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = child.spawn().map_err(|_| ViewerError::Unavailable)?;
        let mut stdin = child.stdin.take().ok_or(ViewerError::DeliveryFailed)?;
        stdin
            .write_all(content.expose().as_bytes())
            .await
            .map_err(|_| ViewerError::DeliveryFailed)?;
        stdin
            .shutdown()
            .await
            .map_err(|_| ViewerError::DeliveryFailed)?;
        let status = child
            .wait()
            .await
            .map_err(|_| ViewerError::DeliveryFailed)?;
        if status.success() {
            Ok(())
        } else {
            Err(ViewerError::DeliveryFailed)
        }
    }
}

/// Runs the native viewer child.  The raw value is read from stdin and is
/// rendered in a native window.  No diagnostic output is emitted.
pub async fn run_native_viewer_process() -> Result<(), NativeViewerError> {
    #[cfg(target_os = "windows")]
    {
        return run_windows_viewer().await;
    }
    #[cfg(target_os = "macos")]
    {
        return run_macos_viewer().await;
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        Err(NativeViewerError::UnsupportedPlatform)
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
async fn read_private_stdin() -> Result<String, NativeViewerError> {
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    let mut stdin = tokio::io::stdin();
    stdin
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| NativeViewerError::Failed)?;
    String::from_utf8(bytes).map_err(|_| NativeViewerError::Failed)
}

#[cfg(target_os = "windows")]
async fn run_windows_viewer() -> Result<(), NativeViewerError> {
    let value = read_private_stdin().await?;
    use windows::{
        Win32::UI::WindowsAndMessaging::{MB_OK, MessageBoxW},
        core::HSTRING,
    };
    let title = HSTRING::from("Hacienda owner disclosure");
    let text = HSTRING::from(value);
    // SAFETY: `HSTRING` owns valid UTF-16 buffers for the duration of the
    // synchronous MessageBoxW call; a null owner HWND is explicitly allowed.
    unsafe {
        MessageBoxW(None, &text, &title, MB_OK);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
async fn run_macos_viewer() -> Result<(), NativeViewerError> {
    let value = read_private_stdin().await?;
    // The script is constant.  The raw value is supplied only on osascript's
    // stdin, never as an argument or environment value.
    const SCRIPT: &str = r#"ObjC.import('Cocoa'); var d=$.NSFileHandle.fileHandleWithStandardInput().readDataToEndOfFile(); var s=$.NSString.alloc.initWithDataEncoding(d,$.NSUTF8StringEncoding).js; var a=$.NSAlert.alloc.init; a.messageText=$.NSString.stringWithUTF8String('Hacienda owner disclosure'); a.informativeText=$.NSString.stringWithString(s); a.addButtonWithTitle('OK'); a.runModal;"#;
    let mut child = Command::new("/usr/bin/osascript");
    child
        .args(["-l", "JavaScript", "-e", SCRIPT])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = child.spawn().map_err(|_| NativeViewerError::Unavailable)?;
    let mut stdin = child.stdin.take().ok_or(NativeViewerError::Failed)?;
    stdin
        .write_all(value.as_bytes())
        .await
        .map_err(|_| NativeViewerError::Failed)?;
    stdin
        .shutdown()
        .await
        .map_err(|_| NativeViewerError::Failed)?;
    child
        .wait()
        .await
        .map_err(|_| NativeViewerError::Failed)?
        .success()
        .then_some(())
        .ok_or(NativeViewerError::Failed)
}

/// OS-backed user presence.  The owner mapping is configuration, not caller
/// input; the platform assertion proves the interactive OS user is present.
#[derive(Clone, Debug)]
pub struct PlatformOwnerPresence {
    tenant_id: String,
    #[cfg(not(target_os = "windows"))]
    principal_id: String,
    #[cfg(target_os = "windows")]
    os_user_to_principal: HashMap<String, String>,
}

impl PlatformOwnerPresence {
    #[cfg(not(target_os = "windows"))]
    pub fn new(principal_id: String, tenant_id: String) -> Self {
        Self {
            principal_id,
            tenant_id,
        }
    }

    /// Bind Windows identities to the authenticated OS account name returned
    /// by the process token, never to a caller-provided principal field.
    #[cfg(target_os = "windows")]
    pub fn for_windows(tenant_id: String, os_user_to_principal: HashMap<String, String>) -> Self {
        Self {
            tenant_id,
            os_user_to_principal,
        }
    }
}

#[async_trait]
impl OwnerPresence for PlatformOwnerPresence {
    async fn verify(
        &self,
        challenge: &DisclosureChallenge,
    ) -> Result<OwnerIdentity, OwnerAuthError> {
        if challenge.expires_at <= chrono::Utc::now().to_rfc3339() {
            return Err(OwnerAuthError::Expired);
        }
        if !cfg!(any(target_os = "windows", target_os = "macos")) {
            return Err(OwnerAuthError::Unavailable);
        }
        let tenant = self.tenant_id.clone();
        #[cfg(target_os = "windows")]
        {
            let challenge = challenge.clone();
            let users = self.os_user_to_principal.clone();
            return tokio::task::spawn_blocking(move || {
                verify_platform(&challenge, &users, &tenant)
            })
            .await
            .map_err(|_| OwnerAuthError::Unavailable)?;
        }
        #[cfg(not(target_os = "windows"))]
        {
            let challenge = challenge.clone();
            let principal = self.principal_id.clone();
            tokio::task::spawn_blocking(move || verify_platform(&challenge, &principal, &tenant))
                .await
                .map_err(|_| OwnerAuthError::Unavailable)?
        }
    }
}

#[cfg(target_os = "macos")]
fn verify_platform(
    challenge: &DisclosureChallenge,
    principal: &str,
    tenant: &str,
) -> Result<OwnerIdentity, OwnerAuthError> {
    use security_framework::passwords::{
        AccessControlOptions, PasswordOptions, delete_generic_password_options, generic_password,
        set_generic_password_options,
    };
    let account = format!("challenge-{}", challenge.nonce);
    let mut set = PasswordOptions::new_generic_password(SERVICE, &account);
    set.set_access_control_options(AccessControlOptions::USER_PRESENCE);
    let expected = blake3::hash(&challenge.canonical_bytes());
    set_generic_password_options(expected.as_bytes(), set)
        .map_err(|_| OwnerAuthError::Unavailable)?;
    let mut get = PasswordOptions::new_generic_password(SERVICE, &account);
    get.set_access_control_options(AccessControlOptions::USER_PRESENCE);
    let actual = generic_password(get).map_err(|_| OwnerAuthError::Invalid)?;
    let _ =
        delete_generic_password_options(PasswordOptions::new_generic_password(SERVICE, &account));
    if actual != expected.as_bytes() {
        return Err(OwnerAuthError::Invalid);
    }
    Ok(OwnerIdentity {
        principal_id: principal.into(),
        tenant_id: tenant.into(),
        method: "macos-keychain-user-presence".into(),
    })
}

#[cfg(target_os = "windows")]
fn verify_platform(
    challenge: &DisclosureChallenge,
    users: &HashMap<String, String>,
    tenant: &str,
) -> Result<OwnerIdentity, OwnerAuthError> {
    use windows::{
        Security::Credentials::UI::{
            UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
        },
        core::HSTRING,
    };
    let digest = blake3::hash(&challenge.canonical_bytes())
        .to_hex()
        .to_string();
    let message = HSTRING::from(format!("Approve Hacienda {}", &digest[..16]));
    let available = UserConsentVerifier::CheckAvailabilityAsync()
        .map_err(|_| OwnerAuthError::Unavailable)?
        .get()
        .map_err(|_| OwnerAuthError::Unavailable)?;
    if available != UserConsentVerifierAvailability::Available {
        return Err(OwnerAuthError::Unavailable);
    }
    let result = UserConsentVerifier::RequestVerificationAsync(&message)
        .map_err(|_| OwnerAuthError::Unavailable)?
        .get()
        .map_err(|_| OwnerAuthError::Unavailable)?;
    if result != UserConsentVerificationResult::Verified {
        return Err(OwnerAuthError::Invalid);
    }
    let user = authenticated_windows_user()?;
    let principal = users.get(&user).ok_or(OwnerAuthError::Invalid)?;
    Ok(OwnerIdentity {
        principal_id: principal.clone(),
        tenant_id: tenant.into(),
        method: "windows-hello-user-presence".into(),
    })
}

#[cfg(target_os = "windows")]
fn authenticated_windows_user() -> Result<String, OwnerAuthError> {
    use windows::{Win32::System::WindowsProgramming::GetUserNameW, core::PWSTR};
    let mut buffer = vec![0u16; 512];
    let mut length = buffer.len() as u32;
    // SAFETY: buffer is writable and its capacity is supplied to the OS; the
    // API writes at most that capacity and reports the resulting UTF-16 length.
    unsafe { GetUserNameW(Some(PWSTR(buffer.as_mut_ptr())), &mut length) }
        .map_err(|_| OwnerAuthError::Unavailable)?;
    let length = length.saturating_sub(1) as usize;
    String::from_utf16(&buffer[..length]).map_err(|_| OwnerAuthError::Invalid)
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn verify_platform(
    _: &DisclosureChallenge,
    _: &str,
    _: &str,
) -> Result<OwnerIdentity, OwnerAuthError> {
    Err(OwnerAuthError::Unavailable)
}

pub type SharedNativeViewerSink = Arc<NativeViewerSink>;
