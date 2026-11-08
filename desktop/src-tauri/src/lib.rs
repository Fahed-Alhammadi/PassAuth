//! Native shell around the web vault: window, menus, tray, and what a WebView can't do safely on its own:
//! requests to the user's server, the OS keychain, a self-clearing clipboard and file saving.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::Serialize;
use tauri::menu::{
    AboutMetadataBuilder, Menu, MenuBuilder, MenuItem, MenuItemBuilder, PredefinedMenuItem,
    SubmenuBuilder,
};
use tauri::tray::TrayIconBuilder;
use tauri::webview::NewWindowResponse;
#[cfg(target_os = "macos")]
use tauri::{ActivationPolicy, RunEvent};
use tauri::{
    AppHandle, Emitter, Listener, Manager, State, Url, WebviewUrl, WebviewWindowBuilder,
    WindowEvent,
};
use tauri_plugin_deep_link::DeepLinkExt;
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_window_state::StateFlags;

const WINDOW: &str = "main";
const KEYCHAIN_SERVICE: &str = "io.passauth.desktop";
const WEBSITE: &str = "https://fahed-alhammadi.github.io/PassAuth/";
const ISSUES: &str = "https://github.com/Fahed-Alhammadi/PassAuth/issues";
const API_TIMEOUT: Duration = Duration::from_secs(30);
const CLIPBOARD_CLEAR: Duration = Duration::from_secs(30);

/// Menu item ids (app menu and tray). The ones the webview acts on are emitted as events of the same name.
const SHOW: &str = "show";
const LOCK: &str = "lock";
const CHANGE_SERVER: &str = "change-server";
const SETTINGS: &str = "settings";
const CHECK_UPDATES: &str = "check-updates";
const HELP: &str = "help";
const REPORT: &str = "report";
const QUIT: &str = "quit";
/// macOS: the AutoFill extension's Keychain access group (its Info.plist `PAKeychainGroup`) and the
/// hand-off item the desktop app writes there (`desktop/macos/AutoFill/MacSignIn.swift` reads it).
#[cfg(target_os = "macos")]
const HANDOFF_GROUP: &str = "JEXQBK3SQ5.io.passauth.desktop.autofill";
#[cfg(target_os = "macos")]
const HANDOFF_SERVICE: &str = "io.passauth.desktop.handoff";
#[cfg(target_os = "macos")]
const HANDOFF_ACCOUNT: &str = "handoff";
/// Webview → shell: `true` while the vault is unlocked. Shell → webview: the window was hidden; the screen was
/// locked, the computer is going to sleep or the user session was switched (vault timeout "On system lock").
const VAULT_STATE: &str = "vault-state";
const WINDOW_HIDDEN: &str = "window-hidden";
#[cfg(target_os = "macos")]
const SYSTEM_LOCK: &str = "system-lock";
/// Shell → webview: the computer woke from sleep (the webview re-checks the server and reconnects).
#[cfg(target_os = "macos")]
const SYSTEM_WAKE: &str = "system-wake";
/// Passed by the login item (autostart plugin): start in the tray without opening the window.
const HIDDEN_ARG: &str = "--hidden";
const SHELL_SETTINGS_FILE: &str = "shell.json";

/// The connected server and the client for it. Only `api_fetch` reaches the network, so the webview can't call other hosts.
struct Server {
    base: Mutex<Option<Url>>,
    client: reqwest::Client,
}

/// "Lock Vault" in the app menu and the tray: enabled only while the vault is unlocked.
struct LockItems(Vec<MenuItem<tauri::Wry>>);

/// What the shell must know before the webview loads, kept in `shell.json` in the app's config directory.
/// `keep_dock` (macOS): keep the Dock icon while the window is closed; off, the app is only in the menu bar then.
struct ShellSettings {
    keep_dock: AtomicBool,
}

#[derive(Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ShellSettingsDto {
    keep_dock: bool,
}

fn shell_settings_path(app: &AppHandle) -> Option<std::path::PathBuf> {
    app.path()
        .app_config_dir()
        .ok()
        .map(|dir| dir.join(SHELL_SETTINGS_FILE))
}

fn load_shell_settings(app: &AppHandle) -> ShellSettingsDto {
    shell_settings_path(app)
        .and_then(|path| std::fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

#[tauri::command]
fn shell_settings_get(settings: State<ShellSettings>) -> ShellSettingsDto {
    ShellSettingsDto {
        keep_dock: settings.keep_dock.load(Ordering::Relaxed),
    }
}

#[tauri::command]
fn shell_settings_set(app: AppHandle, keep_dock: bool) -> Result<(), String> {
    app.state::<ShellSettings>()
        .keep_dock
        .store(keep_dock, Ordering::Relaxed);
    let path = shell_settings_path(&app).ok_or("no config directory")?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_vec(&ShellSettingsDto { keep_dock }).map_err(|e| e.to_string())?;
    std::fs::write(path, json).map_err(|e| e.to_string())?;
    // Applies at once if the window is closed right now.
    let visible = app
        .get_webview_window(WINDOW)
        .is_some_and(|w| w.is_visible().unwrap_or(true));
    apply_dock(&app, visible);
    Ok(())
}

/// macOS: with the window closed and "keep Dock icon" off, the app becomes a menu-bar-only (accessory) app;
/// showing the window makes it a regular app again (Dock icon, app menu, Cmd-Tab).
#[cfg(target_os = "macos")]
fn apply_dock(app: &AppHandle, window_visible: bool) {
    let keep = app
        .state::<ShellSettings>()
        .keep_dock
        .load(Ordering::Relaxed);
    let policy = if window_visible || keep {
        ActivationPolicy::Regular
    } else {
        ActivationPolicy::Accessory
    };
    let _ = app.set_activation_policy(policy);
}

#[cfg(not(target_os = "macos"))]
fn apply_dock(_app: &AppHandle, _window_visible: bool) {}

#[derive(Serialize)]
struct ApiResponse {
    status: u16,
    body: String,
}

/// Remember the server the webview is connected to. Origin only: PassAuth is never served under a sub-path.
#[tauri::command]
fn set_server(server: State<Server>, base: String) -> Result<(), String> {
    let url = Url::parse(&base).map_err(|_| "invalid server address")?;
    let origin_only = url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty();
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() || !origin_only {
        return Err("invalid server address".into());
    }
    *server.base.lock().unwrap() = Some(url);
    Ok(())
}

/// `GET /api{path}` etc. on the connected server. No redirects: a token must never follow one elsewhere.
#[tauri::command]
async fn api_fetch(
    server: State<'_, Server>,
    path: String,
    method: String,
    headers: HashMap<String, String>,
    body: Option<String>,
) -> Result<ApiResponse, String> {
    if !path.starts_with('/') || path.contains("://") {
        return Err("invalid path".into());
    }
    let base = server.base.lock().unwrap().clone().ok_or("no server")?;
    let host = base.host_str().unwrap_or_default().to_string();
    let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| "invalid method")?;
    let mut request = server.client.request(method, format!("{base}api{path}"));
    for (name, value) in headers {
        request = request.header(name, value);
    }
    if let Some(body) = body {
        request = request.body(body);
    }
    let response = request.send().await.map_err(|e| describe(&e, &host))?;
    let status = response.status().as_u16();
    let body = response.text().await.map_err(|e| describe(&e, &host))?;
    Ok(ApiResponse { status, body })
}

/// What the user can act on, instead of reqwest's wording.
fn describe(error: &reqwest::Error, host: &str) -> String {
    if error.is_timeout() {
        return format!("{host} took too long to answer. Check your connection, then try again.");
    }
    let chain = std::iter::successors(Some(error as &dyn std::error::Error), |e| e.source())
        .map(|e| e.to_string().to_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    if chain.contains("certificate") {
        return "The server's certificate isn't trusted by this computer.".into();
    }
    format!("Can't reach {host}. Check the address and your connection, then try again.")
}

/// Keychain errors the webview tells apart: `unavailable` means "use localStorage instead".
fn keychain_error(error: keyring::Error) -> String {
    match error {
        keyring::Error::NoStorageAccess(_)
        | keyring::Error::PlatformFailure(_)
        | keyring::Error::NoDefaultStore => "unavailable".into(),
        other => other.to_string(),
    }
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| e.to_string())?
}

/// Keychain entries are filed under the bundle identifier (`io.passauth.desktop`), so a build with another
/// identifier (a test build) never touches the real app's secrets.
fn entry(app: &AppHandle, name: &str) -> Result<keyring::Entry, String> {
    let service = app.config().identifier.as_str();
    let service = if service.is_empty() {
        KEYCHAIN_SERVICE
    } else {
        service
    };
    keyring::Entry::new(service, name).map_err(keychain_error)
}

#[tauri::command]
async fn secret_get(app: AppHandle, name: String) -> Result<Option<String>, String> {
    blocking(move || match entry(&app, &name)?.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(keychain_error(e)),
    })
    .await
}

#[tauri::command]
async fn secret_set(app: AppHandle, name: String, value: String) -> Result<(), String> {
    blocking(move || {
        entry(&app, &name)?
            .set_password(&value)
            .map_err(keychain_error)
    })
    .await
}

#[tauri::command]
async fn secret_delete(app: AppHandle, name: String) -> Result<(), String> {
    blocking(move || match entry(&app, &name)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(keychain_error(e)),
    })
    .await
}

/// What the desktop app hands the macOS AutoFill extension so it can sign in as its own device without
/// asking for the server, email and Secret Key again. Never tokens or vault keys: the extension gets its
/// own session (a shared refresh token would be flagged as reuse by the server and end both sessions).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Handoff {
    server: String,
    email: String,
    secret_key: Option<String>,
}

#[tauri::command]
async fn autofill_handoff(
    server: String,
    email: String,
    secret_key: Option<String>,
) -> Result<(), String> {
    let json = serde_json::to_vec(&Handoff {
        server,
        email,
        secret_key,
    })
    .map_err(|e| e.to_string())?;
    write_handoff(json).await
}

/// Change server / sign out of the desktop app: the extension keeps its own sign-in, but gets no hint.
#[tauri::command]
async fn autofill_handoff_clear() -> Result<(), String> {
    write_handoff(b"{}".to_vec()).await
}

#[cfg(target_os = "macos")]
async fn write_handoff(json: Vec<u8>) -> Result<(), String> {
    use core_foundation::data::CFData;
    use security_framework::item::{
        ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, ItemUpdateOptions,
        ItemUpdateValue, Location, update_item,
    };
    blocking(move || {
        let data = CFData::from_buffer(&json);
        let mut search = ItemSearchOptions::new();
        search
            .class(ItemClass::generic_password())
            .service(HANDOFF_SERVICE)
            .account(HANDOFF_ACCOUNT)
            .access_group(HANDOFF_GROUP)
            .ignore_legacy_keychains();
        let mut update = ItemUpdateOptions::new();
        update.set_value(ItemUpdateValue::Data(data.clone()));
        if update_item(&search, &update).is_ok() {
            return Ok(());
        }
        let mut add = ItemAddOptions::new(ItemAddValue::Data {
            class: ItemClass::generic_password(),
            data,
        });
        add.set_service(HANDOFF_SERVICE)
            .set_account_name(HANDOFF_ACCOUNT)
            .set_access_group(HANDOFF_GROUP)
            .set_location(Location::DataProtectionKeychain)
            .set_label("PassAuth AutoFill");
        add.add().map_err(|e| e.to_string())
    })
    .await
}

#[cfg(not(target_os = "macos"))]
async fn write_handoff(_json: Vec<u8>) -> Result<(), String> {
    Ok(())
}

/// macOS: tell the webview when the screen locks, the Mac goes to sleep or the user session is switched.
/// Observers live as long as the process (the tokens are never removed).
#[cfg(target_os = "macos")]
fn watch_system_lock(app: AppHandle) {
    use std::ptr::NonNull;

    use block2::RcBlock;
    use objc2_app_kit::{
        NSWorkspace, NSWorkspaceDidWakeNotification, NSWorkspaceSessionDidResignActiveNotification,
        NSWorkspaceWillSleepNotification,
    };
    use objc2_foundation::{NSDistributedNotificationCenter, NSNotification, NSString};

    let woke = app.clone();
    let block = RcBlock::new(move |_: NonNull<NSNotification>| {
        let _ = app.emit(SYSTEM_LOCK, ());
    });
    let wake_block = RcBlock::new(move |_: NonNull<NSNotification>| {
        let _ = woke.emit(SYSTEM_WAKE, ());
    });
    // SAFETY: the blocks capture only an `AppHandle` (Send + Sync) and are kept alive by the leaked observers.
    unsafe {
        let workspace = NSWorkspace::sharedWorkspace().notificationCenter();
        std::mem::forget(workspace.addObserverForName_object_queue_usingBlock(
            Some(NSWorkspaceDidWakeNotification),
            None,
            None,
            &wake_block,
        ));
        for name in [
            NSWorkspaceWillSleepNotification,
            NSWorkspaceSessionDidResignActiveNotification,
        ] {
            std::mem::forget(workspace.addObserverForName_object_queue_usingBlock(
                Some(name),
                None,
                None,
                &block,
            ));
        }
        let screen_locked = NSString::from_str("com.apple.screenIsLocked");
        std::mem::forget(
            NSDistributedNotificationCenter::defaultCenter()
                .addObserverForName_object_queue_usingBlock(
                    Some(&screen_locked),
                    None,
                    None,
                    &block,
                ),
        );
    }
}

/// Copy a secret, kept out of clipboard history, and clear it after 30 s if it's still there.
#[tauri::command]
fn copy_secret(value: String) -> Result<(), String> {
    write_clipboard(value.clone())?;
    std::thread::spawn(move || {
        std::thread::sleep(CLIPBOARD_CLEAR);
        if let Ok(mut clipboard) = arboard::Clipboard::new()
            && clipboard.get().text().is_ok_and(|text| text == value)
        {
            let _ = clipboard.clear();
        }
    });
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn write_clipboard(value: String) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    use arboard::SetExtApple;
    #[cfg(windows)]
    use arboard::SetExtWindows;
    arboard::Clipboard::new()
        .and_then(|mut clipboard| clipboard.set().exclude_from_history().text(value))
        .map_err(|e| e.to_string())
}

/// X11/Wayland hand the data over on request, so a thread keeps offering it until something else is copied.
#[cfg(target_os = "linux")]
fn write_clipboard(value: String) -> Result<(), String> {
    use arboard::SetExtLinux;
    std::thread::spawn(move || {
        if let Ok(mut clipboard) = arboard::Clipboard::new() {
            let _ = clipboard.set().wait().text(value);
        }
    });
    Ok(())
}

/// Save text through the system save dialog. `false` when the user cancels.
#[tauri::command]
async fn save_file(app: AppHandle, filename: String, content: String) -> Result<bool, String> {
    let dialog = app.dialog().file().set_file_name(&filename);
    let picked = tauri::async_runtime::spawn_blocking(move || dialog.blocking_save_file())
        .await
        .map_err(|e| e.to_string())?;
    let Some(path) = picked else { return Ok(false) };
    let path = path.into_path().map_err(|e| e.to_string())?;
    std::fs::write(path, content).map_err(|e| e.to_string())?;
    Ok(true)
}

fn show_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(WINDOW) {
        apply_dock(app, true);
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn open_in_browser(url: &str) {
    let _ = tauri_plugin_opener::open_url(url, None::<&str>);
}

/// Only the app's own pages (and in-page frames) load in the window.
fn allowed_navigation(url: &Url) -> bool {
    match url.scheme() {
        "tauri" | "about" | "blob" => true,
        "http" | "https" => {
            let host = url.host_str().unwrap_or_default();
            host == "tauri.localhost" || (cfg!(debug_assertions) && host == "localhost")
        }
        _ => false,
    }
}

fn launched_hidden() -> bool {
    std::env::args().skip(1).any(|a| a == HIDDEN_ARG)
}

fn build_window(app: &AppHandle) -> tauri::Result<()> {
    WebviewWindowBuilder::new(app, WINDOW, WebviewUrl::default())
        .title("PassAuth")
        .inner_size(1100.0, 760.0)
        .min_inner_size(900.0, 620.0)
        // The login item starts the app in the tray.
        .visible(!launched_hidden())
        .on_navigation(allowed_navigation)
        // Links that would open a new window go to the browser instead.
        .on_new_window(|url, _| {
            if matches!(url.scheme(), "http" | "https") {
                open_in_browser(url.as_str());
            }
            NewWindowResponse::Deny
        })
        // The Import page handles HTML5 drag and drop itself.
        .disable_drag_drop_handler()
        .build()?;
    Ok(())
}

fn lock_item(app: &AppHandle) -> tauri::Result<MenuItem<tauri::Wry>> {
    MenuItemBuilder::with_id(LOCK, "Lock Vault")
        .accelerator("CmdOrCtrl+L")
        .enabled(false)
        .build(app)
}

fn about_item(app: &AppHandle) -> tauri::Result<PredefinedMenuItem<tauri::Wry>> {
    let about = AboutMetadataBuilder::new()
        .name(Some("PassAuth"))
        .version(Some(app.package_info().version.to_string()))
        .copyright(Some("© Fahed Alhammadi"))
        .build();
    PredefinedMenuItem::about(app, Some("About PassAuth"), Some(about))
}

fn build_menu(app: &AppHandle, lock: &MenuItem<tauri::Wry>) -> tauri::Result<Menu<tauri::Wry>> {
    let check_updates = MenuItemBuilder::with_id(CHECK_UPDATES, "Check for Updates…").build(app)?;
    let change_server = MenuItemBuilder::with_id(CHANGE_SERVER, "Change Server…").build(app)?;
    let settings = MenuItemBuilder::with_id(SETTINGS, "Settings…");
    #[cfg(target_os = "macos")]
    let settings = settings.accelerator("Cmd+,");
    let settings = settings.build(app)?;
    let report = MenuItemBuilder::with_id(REPORT, "Report a Problem").build(app)?;
    let about = about_item(app)?;

    #[cfg(target_os = "macos")]
    {
        let app_menu = SubmenuBuilder::new(app, "PassAuth")
            .item(&about)
            .separator()
            .item(&settings)
            .item(&check_updates)
            .separator()
            .hide()
            .hide_others()
            .show_all()
            .separator()
            .quit()
            .build()?;
        let vault = SubmenuBuilder::new(app, "Vault")
            .item(lock)
            .item(&change_server)
            .build()?;
        let edit = SubmenuBuilder::new(app, "Edit")
            .undo()
            .redo()
            .separator()
            .cut()
            .copy()
            .paste()
            .select_all()
            .build()?;
        let window = SubmenuBuilder::new(app, "Window")
            .minimize()
            .maximize()
            .close_window()
            .build()?;
        let help = SubmenuBuilder::new(app, "Help")
            .item(&MenuItemBuilder::with_id(HELP, "PassAuth Help").build(app)?)
            .item(&report)
            .build()?;
        MenuBuilder::new(app)
            .items(&[&app_menu, &vault, &edit, &window, &help])
            .build()
    }
    #[cfg(not(target_os = "macos"))]
    {
        let file = SubmenuBuilder::new(app, "File")
            .item(lock)
            .item(&change_server)
            .separator()
            .item(&settings)
            .separator()
            .item(&MenuItemBuilder::with_id(QUIT, "Exit").build(app)?)
            .build()?;
        let help = SubmenuBuilder::new(app, "Help")
            .item(&check_updates)
            .item(&report)
            .separator()
            .item(&about)
            .build()?;
        MenuBuilder::new(app).items(&[&file, &help]).build()
    }
}

fn build_tray(app: &AppHandle, lock: &MenuItem<tauri::Wry>) -> tauri::Result<()> {
    let menu = MenuBuilder::new(app)
        .item(&MenuItemBuilder::with_id(SHOW, "Open PassAuth").build(app)?)
        .item(lock)
        .separator()
        .item(&MenuItemBuilder::with_id(CHECK_UPDATES, "Check for Updates…").build(app)?)
        .separator()
        .item(&MenuItemBuilder::with_id(QUIT, "Quit PassAuth").build(app)?)
        .build()?;
    let tray = TrayIconBuilder::with_id("main")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .tooltip("PassAuth")
        // Receives every menu event (app menu included), so this is the one menu handler.
        .on_menu_event(|app, event| handle_menu(app, event.id().as_ref()));
    #[cfg(target_os = "macos")]
    let tray = tray
        .icon(tauri::image::Image::from_bytes(include_bytes!(
            "../icons/tray-template.png"
        ))?)
        .icon_as_template(true);
    #[cfg(not(target_os = "macos"))]
    let tray = tray.icon(app.default_window_icon().cloned().expect("bundle icon"));
    tray.build(app)?;
    Ok(())
}

fn handle_menu(app: &AppHandle, id: &str) {
    match id {
        SHOW => show_window(app),
        LOCK => {
            let _ = app.emit(LOCK, ());
        }
        CHANGE_SERVER | SETTINGS | CHECK_UPDATES => {
            show_window(app);
            let _ = app.emit(id, ());
        }
        HELP => open_in_browser(WEBSITE),
        REPORT => open_in_browser(ISSUES),
        QUIT => app.exit(0),
        _ => {}
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // reqwest is built without a TLS provider (like the updater); ring serves both.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(API_TIMEOUT)
        .build()
        .expect("http client");

    tauri::Builder::default()
        .manage(Server {
            base: Mutex::new(None),
            client,
        })
        // First, so a second launch is caught before anything else starts. Its `deep-link` feature hands a link
        // that launched the second instance (Windows, Linux) to the deep-link plugin before calling this.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_window(app)
        }))
        // otpauth:// and apple-otpauth:// links (schemes in tauri.conf.json): the webview reads them with
        // `getCurrent` / `onOpenUrl` and offers to add the verification code to a login.
        .plugin(tauri_plugin_deep_link::init())
        // Size and position only: a window hidden at quit must still appear on the next launch.
        .plugin(
            tauri_plugin_window_state::Builder::default()
                .with_state_flags(StateFlags::all() - StateFlags::VISIBLE)
                .build(),
        )
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        // "Start at login" (Settings → This app): a login item that launches the app hidden in the tray.
        .plugin(
            tauri_plugin_autostart::Builder::new()
                .args([HIDDEN_ARG])
                .build(),
        )
        .invoke_handler(tauri::generate_handler![
            set_server,
            api_fetch,
            secret_get,
            secret_set,
            secret_delete,
            copy_secret,
            save_file,
            shell_settings_get,
            shell_settings_set,
            autofill_handoff,
            autofill_handoff_clear
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            app.manage(ShellSettings {
                keep_dock: AtomicBool::new(load_shell_settings(&handle).keep_dock),
            });
            let menu_lock = lock_item(&handle)?;
            let tray_lock = lock_item(&handle)?;
            app.set_menu(build_menu(&handle, &menu_lock)?)?;
            build_tray(&handle, &tray_lock)?;
            build_window(&handle)?;
            if launched_hidden() {
                apply_dock(&handle, false);
            }
            app.manage(LockItems(vec![menu_lock, tray_lock]));
            #[cfg(target_os = "macos")]
            watch_system_lock(handle.clone());
            let shown = handle.clone();
            app.deep_link().on_open_url(move |_| show_window(&shown));
            // deb/rpm and the Windows installer register the schemes; an AppImage has to do it itself.
            #[cfg(target_os = "linux")]
            if handle.env().appimage.is_some()
                && let Err(e) = app.deep_link().register_all()
            {
                eprintln!("couldn't register the otpauth link handler: {e}");
            }
            app.listen(VAULT_STATE, move |event| {
                let unlocked = event.payload() == "true";
                for item in &handle.state::<LockItems>().0 {
                    let _ = item.set_enabled(unlocked);
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing hides the window; the app stays in the tray (and, if the user keeps it, the macOS Dock).
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
                apply_dock(window.app_handle(), false);
                let _ = window.emit(WINDOW_HIDDEN, ());
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building PassAuth")
        .run(|app, event| {
            #[cfg(target_os = "macos")]
            if let RunEvent::Reopen { .. } = event {
                show_window(app);
            }
            #[cfg(not(target_os = "macos"))]
            let _ = (app, event);
        });
}
