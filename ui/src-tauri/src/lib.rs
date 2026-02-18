// MYTH Desktop Application — Tauri v2 Core Library
// Industry-Grade Cybersecurity AI Agent Desktop Shell

mod integrity;
mod crypto;
mod license;
mod updater;
mod crash;

use tauri::Manager;
use tauri::Emitter;
use log::info;

/// Tauri command: Get the current application version
#[tauri::command]
fn get_app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Tauri command: Get the machine hardware fingerprint
#[tauri::command]
fn get_machine_id() -> Result<String, String> {
    machine_uid::get().map_err(|e| format!("Failed to get machine ID: {}", e))
}

/// Tauri command: Check if running in desktop mode
#[tauri::command]
fn is_desktop() -> bool {
    true
}

/// Build and run the Tauri application
pub fn run() {
    // Install panic hook for crash reporting (Feature 15)
    crash::install_panic_hook();

    tauri::Builder::default()
        // --- Plugins ---
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_log::Builder::new().build())
        // --- Setup ---
        .setup(|app| {
            info!("⌬ [MYTH] Desktop shell initializing...");

            // 1. Crash recovery check (Feature 17)
            let app_handle = app.handle().clone();
            let crash_detected = crash::check_abnormal_shutdown(&app_handle);
            if crash_detected {
                info!("⚠️ [MYTH] Previous abnormal shutdown detected — session memory was cleared");
            }

            // 2. Runtime integrity check (Feature 2)
            match integrity::verify_integrity(&app_handle) {
                Ok(true) => info!("✅ [MYTH] Integrity check passed"),
                Ok(false) => {
                    log::error!("🚨 [MYTH] Integrity check FAILED — application may be corrupted");
                    // In production, show dialog and refuse to run
                    // For development, we log and continue
                }
                Err(e) => {
                    log::warn!("⚠️ [MYTH] Integrity check skipped: {}", e);
                }
            }

            // 3. License verification (Feature 11)
            let license_valid = license::verify_license_on_startup(&app_handle);
            info!(
                "🔑 [MYTH] License status: {}",
                if license_valid { "VALID" } else { "REQUIRES_ACTIVATION" }
            );

            // 4. Write session lock file for crash detection
            crash::write_session_lock(&app_handle);

            // 5. Spawn Python FastAPI backend sidecar
            let app_handle_sidecar = app_handle.clone();
            tauri::async_runtime::spawn(async move {
                spawn_backend_sidecar(app_handle_sidecar).await;
            });

            // 6. Store crash detection flag for frontend
            app.manage(AppState {
                crash_detected,
                license_valid,
            });

            info!("⌬ [MYTH] Desktop shell ready");
            Ok(())
        })
        // --- IPC Commands ---
        .invoke_handler(tauri::generate_handler![
            get_app_version,
            get_machine_id,
            is_desktop,
            // Integrity
            integrity::check_integrity,
            integrity::generate_integrity_manifest,
            // Crypto
            crypto::encrypt_data,
            crypto::decrypt_data,
            crypto::save_encrypted_file,
            crypto::load_encrypted_file,
            // License
            license::activate_license,
            license::verify_license,
            license::get_license_info,
            license::deactivate_license,
            // Updater
            updater::check_for_updates,
            updater::check_minimum_version,
            updater::check_maintenance_mode,
            // Crash
            crash::get_crash_info,
            crash::report_crash,
            // State
            get_app_state,
        ])
        .build(tauri::generate_context!())
        .expect("Failed to build MYTH desktop application")
        .run(|_app_handle, event| {
            if let tauri::RunEvent::Exit = event {
                // Clean shutdown — remove session lock (Feature 20)
                info!("⌬ [MYTH] Clean shutdown — removing session lock");
                crash::remove_session_lock();
            }
        });
}

/// Application-wide shared state
pub struct AppState {
    pub crash_detected: bool,
    pub license_valid: bool,
}

#[tauri::command]
fn get_app_state(state: tauri::State<'_, AppState>) -> serde_json::Value {
    serde_json::json!({
        "crash_detected": state.crash_detected,
        "license_valid": state.license_valid,
        "version": env!("CARGO_PKG_VERSION"),
    })
}

/// Spawn the Python FastAPI backend as a managed sidecar process
async fn spawn_backend_sidecar(app: tauri::AppHandle) {
    use tauri_plugin_shell::ShellExt;

    info!("🚀 [SIDECAR] Launching Python FastAPI backend...");

    // The sidecar binary is the packaged Python backend
    // In development, we use the Python interpreter directly
    let shell = app.shell();

    // Try to spawn the sidecar (packaged binary)
    match shell.sidecar("binaries/myth-backend") {
        Ok(command) => {
            match command.args(["--host", "127.0.0.1", "--port", "8890"]).spawn() {
                Ok((_rx, child)) => {
                    info!("✅ [SIDECAR] Backend sidecar spawned (PID: {:?})", child.pid());

                    // Health check loop
                    let client = reqwest::Client::new();
                    let mut retries = 0;
                    let max_retries = 150; // 300 seconds

                    loop {
                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

                        match client
                            .get("http://127.0.0.1:8890/health")
                            .timeout(std::time::Duration::from_secs(5))
                            .send()
                            .await
                        {
                            Ok(resp) if resp.status().is_success() => {
                                if let Ok(body) = resp.json::<serde_json::Value>().await {
                                    if body.get("ready").and_then(|v| v.as_bool()).unwrap_or(false) {
                                        info!("✅ [SIDECAR] Backend is READY");
                                        // Emit event to frontend
                                        let _ = app.emit("backend-ready", serde_json::json!({"ready": true}));
                                        break;
                                    } else {
                                        let components = body.get("components").cloned().unwrap_or_default();
                                        info!("⏳ [SIDECAR] Backend loading... {:?}", components);
                                    }
                                }
                            }
                            _ => {
                                if retries % 5 == 0 {
                                    info!("⏳ [SIDECAR] Waiting for backend ({}s)...", retries * 2);
                                }
                            }
                        }

                        retries += 1;
                        if retries >= max_retries {
                            log::error!("❌ [SIDECAR] Backend failed to start within 300s");
                            let _ = app.emit("backend-error", serde_json::json!({"error": "Backend startup timeout"}));
                            break;
                        }
                    }
                }
                Err(e) => {
                    log::error!("❌ [SIDECAR] Failed to spawn backend: {}", e);
                    let _ = app.emit("backend-error", serde_json::json!({"error": format!("Spawn failed: {}", e)}));
                }
            }
        }
        Err(e) => {
            log::warn!("⚠️ [SIDECAR] Sidecar binary not found ({}). Assuming dev mode — backend should be started manually.", e);
            let _ = app.emit("backend-dev-mode", serde_json::json!({"message": "Dev mode: start backend manually"}));
        }
    }
}
