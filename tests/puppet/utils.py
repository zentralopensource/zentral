from datetime import datetime, timedelta
import uuid
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.utils.crypto import get_random_string


def build_self_signed_cert(name):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])
    serialized_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(name)]),
        critical=False,
    ).sign(
        key, hashes.SHA256()
    ).public_bytes(serialization.Encoding.PEM).decode("ascii").strip()  # strip() because it is submitted in forms
    serialized_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode("ascii")  # no strip(). we keep the full info
    return serialized_cert, serialized_key


def build_report(host=None, time='2022-02-16T17:37:47.337045569Z'):
    return {
        'cached_catalog_status': 'not_used',
        'catalog_uuid': str(uuid.uuid4()),
        'code_id': 'urn:puppet:code-id:1:{};development'.format(str(uuid.uuid4()).replace("-", "")),
        'configuration_version': 'pe-master.example.com-development-{}'.format(get_random_string(8)),
        'corrective_change': False,
        'environment': 'development',
        'host': host or get_random_string(12),
        'logs': [],
        'master_used': 'pe-master.example.com:8140',
        'metrics': [],
        'noop': False,
        'noop_pending': False,
        'puppet_version': '7.12.1',
        'report_format': 12,
        'resource_statuses': [],
        'server_used': 'pe-master.example.com:8140',
        'status': 'unchanged',
        'time': time,
        'transaction_completed': True,
        'transaction_uuid': str(uuid.uuid4())
    }
