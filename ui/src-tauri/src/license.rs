// MYTH Desktop — Product Activation & Licensing (Features 9-14)
// Key-based licensing with Ed25519 signatures, hardware binding, and tamper protection.

use ed25519_dalek::{VerifyingKey, Signature, Verifier, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use base64::Engine;
use std::fs;
use std::path::PathBuf;
use tauri::AppHandle;
use log::{info, warn};

/// License certificate stored on disk (encrypted)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LicenseCertificate {
    pub activation_key: String,
    pub device_fingerprint: String,
    pub license_tier: String,
    pub expiration: Option<String>, // ISO 8601 date or null for perpetual
    pub issued_at: String,
    pub signature: String, // Base64-encoded Ed25519 signature
}

/// License server response
#[derive(Debug, Serialize, Deserialize)]
struct ActivationResponse {
    success: bool,
    certificate: Option<LicenseCertificate>,
    error: Option<String>,
}

/// Embedded public verification key (Ed25519)
/// In production, replace this with your actual public key
const VERIFICATION_PUB_KEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// License server base URL
const LICENSE_SERVER_URL: &str = "https://license.myth.github.io/api/v1";

/// Get the license file path
fn get_license_path() -> Result<PathBuf, String> {
    let base = dirs::data_local_dir()
        .ok_or_else(|| "Cannot resolve local data directory".to_string())?;
    let dir = base.join("MYTH");
    fs::create_dir_all(&dir).map_err(|e| format!("Cannot create dir: {}", e))?;
    Ok(dir.join("license.myth"))
}

/// Get hardware fingerprint for this machine
fn get_device_fingerprint() -> Result<String, String> {
    let machine_id = machine_uid::get()
        .map_err(|e| format!("Failed to get machine ID: {}", e))?;

    // Hash the machine ID for privacy
    let mut hasher = Sha256::new();
    hasher.update(machine_id.as_bytes());
    hasher.update(b"MYTH_DEVICE_FP_v1");
    let result = hasher.finalize();

    Ok(format!("{:x}", result)[..32].to_string())
}

/// Verify the Ed25519 signature on a license certificate
fn verify_signature(cert: &LicenseCertificate) -> Result<bool, String> {
    // Construct the signed payload (same as server-side)
    let payload = format!(
        "{}:{}:{}:{}:{}",
        cert.activation_key,
        cert.device_fingerprint,
        cert.license_tier,
        cert.expiration.as_deref().unwrap_or("perpetual"),
        cert.issued_at
    );

    // Decode the public key
    let pub_key_bytes = hex::decode(VERIFICATION_PUB_KEY_HEX)
        .map_err(|e| format!("Invalid public key hex: {}", e))?;

    if pub_key_bytes.len() != PUBLIC_KEY_LENGTH {
        return Err("Invalid public key length".to_string());
    }

    let mut key_arr = [0u8; PUBLIC_KEY_LENGTH];
    key_arr.copy_from_slice(&pub_key_bytes);

    let verifying_key = VerifyingKey::from_bytes(&key_arr)
        .map_err(|e| format!("Invalid public key: {}", e))?;

    // Decode the signature
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&cert.signature)
        .map_err(|e| format!("Invalid signature base64: {}", e))?;

    if sig_bytes.len() != SIGNATURE_LENGTH {
        return Err("Invalid signature length".to_string());
    }

    let mut sig_arr = [0u8; SIGNATURE_LENGTH];
    sig_arr.copy_from_slice(&sig_bytes);

    let signature = Signature::from_bytes(&sig_arr);

    // Verify
    match verifying_key.verify(payload.as_bytes(), &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Save license certificate to disk (encrypted with machine-bound key)
fn save_license(cert: &LicenseCertificate) -> Result<(), String> {
    let path = get_license_path()?;
    let json = serde_json::to_string_pretty(cert)
        .map_err(|e| format!("Serialize failed: {}", e))?;

    // Encrypt using the crypto module's machine-bound encryption
    let encrypted = super::crypto::encrypt_data(json)?;

    fs::write(&path, &encrypted)
        .map_err(|e| format!("Write failed: {}", e))?;

    info!("🔑 [MYTH] Certificate saved to {}", path.display());
    Ok(())
}

/// Load license certificate from disk
fn load_license() -> Result<Option<LicenseCertificate>, String> {
    let path = get_license_path()?;

    if !path.exists() {
        return Ok(None);
    }

    let encrypted = fs::read_to_string(&path)
        .map_err(|e| format!("Read failed: {}", e))?;

    match super::crypto::decrypt_data(encrypted) {
        Ok(json) => {
            let cert: LicenseCertificate = serde_json::from_str(&json)
                .map_err(|e| format!("Parse failed: {}", e))?;
            Ok(Some(cert))
        }
        Err(e) => {
            warn!("⚠️ [MYTH] Cannot decrypt license (machine changed?): {}", e);
            Ok(None)
        }
    }
}

/// Verify license on application startup (Features 11-14)
pub fn verify_license_on_startup(_app: &AppHandle) -> bool {
    match load_license() {
        Ok(Some(cert)) => {
            // 1. Verify device fingerprint matches this machine (Feature 12)
            let current_fp = get_device_fingerprint().unwrap_or_default();
            if cert.device_fingerprint != current_fp {
                warn!("🚨 [MYTH] Device fingerprint mismatch — license invalid on this machine");
                return false;
            }

            // 2. Check expiration (Feature 11)
            if let Some(ref expiry) = cert.expiration {
                if let Ok(exp_date) = chrono::NaiveDate::parse_from_str(expiry, "%Y-%m-%d") {
                    let today = chrono::Local::now().date_naive();
                    if today > exp_date {
                        warn!("🚨 [MYTH] License expired on {}", expiry);
                        return false;
                    }
                }
            }

            // 3. Verify signature (Feature 14 — tamper protection)
            // Skip signature verification if using placeholder key (dev mode)
            if VERIFICATION_PUB_KEY_HEX == "0000000000000000000000000000000000000000000000000000000000000000" {
                info!("⚠️ [MYTH] Dev mode — skipping signature verification");
                return true;
            }

            match verify_signature(&cert) {
                Ok(true) => {
                    info!("✅ [MYTH] Valid license: tier={}, device={}", cert.license_tier, &cert.device_fingerprint[..8]);
                    true
                }
                Ok(false) => {
                    warn!("🚨 [MYTH] Signature verification failed — license tampered");
                    false
                }
                Err(e) => {
                    warn!("⚠️ [MYTH] Signature check error: {}", e);
                    false
                }
            }
        }
        Ok(None) => {
            info!("🔑 [MYTH] No license found — activation required");
            false
        }
        Err(e) => {
            warn!("⚠️ [MYTH] Error loading license: {}", e);
            false
        }
    }
}

/// Tauri IPC: Activate license with a key (Feature 9-10)
#[tauri::command]
pub async fn activate_license(key: String) -> Result<serde_json::Value, String> {
    let device_fp = get_device_fingerprint()?;

    info!("🔑 [MYTH] Activating key: {}... (device: {}...)",
        &key[..key.len().min(8)], &device_fp[..8]);

    // Send activation request to license server
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/activate", LICENSE_SERVER_URL))
        .json(&serde_json::json!({
            "activation_key": key,
            "device_fingerprint": device_fp,
            "app_version": env!("CARGO_PKG_VERSION"),
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Server unreachable: {}", e))?;

    if !response.status().is_success() {
        return Ok(serde_json::json!({
            "success": false,
            "error": format!("Server returned status {}", response.status())
        }));
    }

    let activation: ActivationResponse = response
        .json()
        .await
        .map_err(|e| format!("Invalid server response: {}", e))?;

    if activation.success {
        if let Some(cert) = &activation.certificate {
            save_license(cert)?;
            Ok(serde_json::json!({
                "success": true,
                "tier": cert.license_tier,
                "expiration": cert.expiration,
                "device_fingerprint": &cert.device_fingerprint[..8]
            }))
        } else {
            Err("Server returned success but no certificate".to_string())
        }
    } else {
        Ok(serde_json::json!({
            "success": false,
            "error": activation.error.unwrap_or_else(|| "Unknown error".to_string())
        }))
    }
}

/// Tauri IPC: Verify current license status (Feature 11)
#[tauri::command]
pub fn verify_license() -> Result<serde_json::Value, String> {
    match load_license() {
        Ok(Some(cert)) => {
            let current_fp = get_device_fingerprint().unwrap_or_default();
            let fp_match = cert.device_fingerprint == current_fp;
            let expired = if let Some(ref exp) = cert.expiration {
                chrono::NaiveDate::parse_from_str(exp, "%Y-%m-%d")
                    .map(|d| chrono::Local::now().date_naive() > d)
                    .unwrap_or(false)
            } else {
                false
            };

            Ok(serde_json::json!({
                "has_license": true,
                "valid": fp_match && !expired,
                "tier": cert.license_tier,
                "expiration": cert.expiration,
                "device_match": fp_match,
                "expired": expired
            }))
        }
        Ok(None) => Ok(serde_json::json!({
            "has_license": false,
            "valid": false
        })),
        Err(e) => Ok(serde_json::json!({
            "has_license": false,
            "valid": false,
            "error": e
        }))
    }
}

/// Tauri IPC: Get license info for display
#[tauri::command]
pub fn get_license_info() -> Result<serde_json::Value, String> {
    let device_fp = get_device_fingerprint().unwrap_or_else(|_| "unknown".to_string());

    match load_license() {
        Ok(Some(cert)) => Ok(serde_json::json!({
            "activated": true,
            "tier": cert.license_tier,
            "expiration": cert.expiration,
            "device_id": &device_fp[..device_fp.len().min(16)],
            "issued_at": cert.issued_at
        })),
        _ => Ok(serde_json::json!({
            "activated": false,
            "device_id": &device_fp[..device_fp.len().min(16)]
        }))
    }
}

/// Tauri IPC: Deactivate / remove license (for re-activation)
#[tauri::command]
pub fn deactivate_license() -> Result<bool, String> {
    let path = get_license_path()?;
    if path.exists() {
        fs::remove_file(&path).map_err(|e| format!("Remove failed: {}", e))?;
        info!("🔑 [MYTH] License deactivated");
    }
    Ok(true)
}

/// Hex decode helper (since we don't want to add the `hex` crate)
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("Odd-length hex string".to_string());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }
}
