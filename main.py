# SECURE MESSAGING SIMULATION
# ECDH (X25519) + AES-256-GCM

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# HKDF (Key Derivation)
def derive_session_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=None,
        info=b"secure-chat",
    )
    return hkdf.derive(shared_secret)

# Generate Key Pair
def generate_keypair():
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return private_key, public_bytes


def main():
    print("=== SIMULASI SECURE MESSAGING (ECDH + AES-256-GCM) ===\n")

    # 1. Generate key Alice & Bob
    alice_priv, alice_pub = generate_keypair()
    bob_priv, bob_pub = generate_keypair()

    print(f"[Alice] Public Key: {alice_pub.hex()[:10]}...")
    print(f"[Bob] Public Key: {bob_pub.hex()[:10]}...\n")

    # 2. Key Exchange (ECDH)
    bob_public_obj = X25519PublicKey.from_public_bytes(bob_pub)
    alice_public_obj = X25519PublicKey.from_public_bytes(alice_pub)

    shared_alice = alice_priv.exchange(bob_public_obj)
    shared_bob = bob_priv.exchange(alice_public_obj)

    print(f"[Shared Secret] Alice: {shared_alice.hex()[:10]}...")
    print(f"[Shared Secret] Bob:   {shared_bob.hex()[:10]}...")
    print(f"Sama? {shared_alice == shared_bob}\n")

    # 3. Derive Session Key
    key_alice = derive_session_key(shared_alice)
    key_bob = derive_session_key(shared_bob)

    print(f"[Session Key] Alice: {key_alice.hex()[:10]}...")
    print(f"[Session Key] Bob:   {key_bob.hex()[:10]}...")
    print(f"Sama? {key_alice == key_bob}\n")

    # 4. Enkripsi Pesan (Alice)
    pesan = input("[Alice] Masukkan pesan: Tes pesan rahasia").encode()

    aesgcm = AESGCM(key_alice)
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(nonce, pesan, None)

    print(f"\n[Alice] Ciphertext:")
    print(f"nonce = {nonce.hex()[:10]}...")
    print(f"ct    = {ciphertext.hex()[:10]}...\n")

    # 5. Dekripsi (Bob)
    aesgcm_bob = AESGCM(key_bob)
    decrypted = aesgcm_bob.decrypt(nonce, ciphertext, None)

    print(f"[Bob] Terdekripsi: {decrypted.decode()} ✓")

    # 6. BUKTI ISOLASI SESSION
    print("\n=== SIMULASI SESSION BARU ===")

    # Generate key baru (Bob baru)
    bob_priv_new, bob_pub_new = generate_keypair()

    try:
        # coba decrypt pesan lama pakai key baru
        bob_new_pub_obj = X25519PublicKey.from_public_bytes(alice_pub)
        shared_new = bob_priv_new.exchange(bob_new_pub_obj)

        key_new = derive_session_key(shared_new)

        aesgcm_new = AESGCM(key_new)
        aesgcm_new.decrypt(nonce, ciphertext, None)

        print("❌ ERROR: Harusnya tidak bisa decrypt!")
    except Exception:
        print("[Session baru] Gagal decrypt pesan lama ✓")

    # buat session baru beneran
    shared_new2 = alice_priv.exchange(
        X25519PublicKey.from_public_bytes(bob_pub_new)
    )
    key_new2 = derive_session_key(shared_new2)

    print(f"[Session baru] Key berbeda: {key_new2.hex()[:10]}...")

# RUN
if __name__ == "__main__":
    main()