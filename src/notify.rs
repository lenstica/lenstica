use anyhow::Result;

/// Show a desktop notification.
///
/// On macOS a notification shows the icon of the app it is attributed to.
/// When `Lenstica.app` is installed (anywhere LaunchServices knows about,
/// e.g. ~/Applications), notifications are posted as that app, so they carry
/// its name and icon and are managed under System Settings → Notifications →
/// Lenstica, whether they come from the menu bar app or the CLI.
///
/// Apple's newer User Notifications API would need the app signed with an
/// Apple Developer ID; for an ad-hoc signed build it refuses ("Notifications
/// are not allowed for this application"), so this uses the older
/// NSUserNotification path, which posts on behalf of a bundle identifier.
/// Without the app, `osascript` is the fallback; it shows no icon.
#[cfg(target_os = "macos")]
pub fn send(title: &str, body: &str) -> Result<()> {
    match as_app(title, body) {
        Ok(true) => Ok(()),
        Ok(false) => osascript(title, body),
        Err(e) => {
            eprintln!("lenstica: notification as Lenstica.app failed ({e}); using osascript");
            osascript(title, body)
        }
    }
}

/// How notifications are delivered from this process, for `lenstica test-notification`.
#[cfg(target_os = "macos")]
pub fn route() -> &'static str {
    if app_installed() {
        "as Lenstica.app, with its icon"
    } else {
        "with osascript, without an icon: install Lenstica.app (e.g. in ~/Applications) to get one"
    }
}

#[cfg(not(target_os = "macos"))]
pub fn route() -> &'static str {
    "through the desktop notification service"
}

#[cfg(target_os = "macos")]
fn app_installed() -> bool {
    use std::sync::OnceLock;
    // Attribution is process-wide and can be set once.
    static APP: OnceLock<bool> = OnceLock::new();
    *APP.get_or_init(|| {
        let found = mac_notification_sys::get_bundle_identifier("Lenstica");
        found.as_deref() == Some(BUNDLE_ID)
            && mac_notification_sys::set_application(BUNDLE_ID).is_ok()
    })
}

/// The bundle identifier in tauri.conf.json.
#[cfg(target_os = "macos")]
const BUNDLE_ID: &str = "com.lenstica.app";

/// Post as Lenstica.app; `Ok(false)` when the app is not installed.
#[cfg(target_os = "macos")]
fn as_app(title: &str, body: &str) -> Result<bool> {
    let installed = app_installed();
    if !installed {
        return Ok(false);
    }
    mac_notification_sys::Notification::new()
        .title(title)
        .message(body)
        .default_sound()
        .asynchronous(true)
        .send()?;
    Ok(true)
}

#[cfg(target_os = "macos")]
fn osascript(title: &str, body: &str) -> Result<()> {
    use anyhow::{Context, bail};
    // osascript ships with every macOS and needs no app bundle or entitlement.
    let quote = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
    let script = format!(
        "display notification {} with title {}",
        quote(body),
        quote(title)
    );
    let out = std::process::Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(script)
        .output()
        .context("cannot run osascript")?;
    if !out.status.success() {
        bail!("osascript: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn send(title: &str, body: &str) -> Result<()> {
    notify_rust::Notification::new()
        .appname("Lenstica")
        .summary(title)
        .body(body)
        .show()?;
    Ok(())
}
