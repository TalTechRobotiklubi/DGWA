import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa


def main():
    # Directory prefix for storing certificates and keys
    directory_prefix = "data/"

    # Ensure the directory exists
    output_dir = Path(directory_prefix)
    output_dir.mkdir(parents=True, exist_ok=True)

    cert_path = output_dir / "cert.pem"
    key_path = output_dir / "key.pem"

    # Check if the certificate and key files already exist
    cert_exists = cert_path.exists()
    key_exists = key_path.exists()

    if cert_exists and key_exists:
        print(f"Both certificate and key files already exist ({cert_path}, {key_path}), exiting.")
        return
    elif cert_exists:
        print(f"Certificate file already exists ({cert_path}).")
        # If only the certificate exists, we could decide to abort or proceed.
        # The original code proceeds, but here we will also abort to avoid mismatches.
        print("Existing certificate found without a matching key. Please remove or rename it before generating a new key/certificate pair.")
        return
    elif key_exists:
        print(f"Key file already exists ({key_path}).")
        print("Existing key found without a matching certificate. Please remove or rename it before generating a new certificate/key pair.")
        return

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Create a self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Write private key to file
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Write certificate to file
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))

    print(f"Self-signed certificate and key have been generated:\n  Certificate: {cert_path}\n  Key: {key_path}")


if __name__ == "__main__":
    main()
