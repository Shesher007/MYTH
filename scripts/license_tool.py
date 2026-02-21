import base64
import json
from datetime import datetime, timedelta

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError:
    print(
        "❌ Error: 'cryptography' library not found. Please run: uv pip install cryptography"
    )
    exit(1)


def generate_keypair():
    """Generates an Ed25519 keypair for signing licenses."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes_raw()
    pub_bytes = public_key.public_bytes_raw()

    return priv_bytes.hex(), pub_bytes.hex()


def create_certificate(priv_key_hex, activation_key, device_fp, tier="Pro", days=365):
    """Creates a signed LicenseCertificate JSON."""
    issued_at = datetime.utcnow().isoformat() + "Z"
    expiration = (
        (datetime.utcnow() + timedelta(days=days)).strftime("%Y-%m-%d")
        if days > 0
        else "perpetual"
    )

    # Payload format must match Rust: {key}:{device_fp}:{tier}:{expiration}:{issued_at}
    payload = f"{activation_key}:{device_fp}:{tier}:{expiration}:{issued_at}"

    # Sign
    priv_bytes = bytes.fromhex(priv_key_hex)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    signature = private_key.sign(payload.as_bytes())
    sig_b64 = base64.b64encode(signature).decode("utf-8")

    cert = {
        "activation_key": activation_key,
        "device_fingerprint": device_fp,
        "license_tier": tier,
        "expiration": expiration if expiration != "perpetual" else None,
        "issued_at": issued_at,
        "signature": sig_b64,
    }

    return cert


def main():
    print("⌬ MYTH Licensing Tool — Official Key Management")
    print("-" * 45)
    print("1. Generate new Master Signing Keys")
    print("2. Issue a signed License Certificate (for a customer)")
    choice = input("\nSelect an option: ")

    if choice == "1":
        priv, pub = generate_keypair()
        print("\n✅ New Master Keys Generated!")
        print(f"PRIVATE KEY (Keep Secret!): {priv}")
        print(f"PUBLIC KEY (Put in license.rs): {pub}")
        print(
            "\nIMPORTANT: Update VERIFICATION_PUB_KEY_HEX in 'ui/src-tauri/src/license.rs' with this public key."
        )

    elif choice == "2":
        priv = input("Enter your Private Signing Key (hex): ")
        key = input("Enter Activation Key (e.g. MYTH-XXXX-YYYY): ")
        fp = input("Enter Customer Device Fingerprint (from app activation screen): ")
        tier = input("License Tier [Pro/Premium/Elite]: ") or "Pro"

        cert = create_certificate(priv, key, fp, tier)
        print("\n✅ Certificate Created!")
        print(json.dumps(cert, indent=2))
        print(
            "\nSave this as 'license.myth' (after encryption) or return it from your activation server."
        )


if __name__ == "__main__":
    main()
