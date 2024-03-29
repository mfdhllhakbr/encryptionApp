from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def generate_rsa_keys():
    # Generate RSA private key with key length of 256 bits
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=512,
        backend=default_backend()
    )

    # Extract the private and public keys
    public_key = private_key.public_key()

    # Serialize keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem

# Example usage
private_key, public_key = generate_rsa_keys()

# Convert bytes to UTF-8 string
private_key_utf8 = private_key.decode('utf-8')
public_key_utf8 = public_key.decode('utf-8')

# Print keys
print("Private Key:")
print(private_key_utf8)
print("\nPublic Key:")
print(public_key_utf8)
