import asn1
from datetime import datetime, timedelta
import subprocess
import base64
from io import BytesIO

import itertools

sphincs_variants = list(itertools.product(
            ['sha256', 'shake256', 'haraka'],
            ['128s', '128f', '192s', '192f', '256s', '256f'],
            ['simple', 'robust']))

oids = {
    var: i
    for (i, var) in enumerate(
        f"sphincs{hash}{size}{type}"
        for (hash, size, type)
        in sphincs_variants)
}


def public_key_der(algorithm, pk):
    encoder = asn1.Encoder()
    encoder.start()
    write_public_key(encoder, algorithm, pk)
    return encoder.output()


def private_key_der(algorithm, sk):
    encoder = asn1.Encoder()
    encoder.start()
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(0, asn1.Numbers.Integer)
    encoder.enter(asn1.Numbers.Sequence)  # AlgorithmIdentifier
    # FIXME: This should be parameterized
    oid = oids[algorithm]
    encoder.write(f'1.2.6.1.4.1.311.89.2.{16128 + oid}',
                  asn1.Numbers.ObjectIdentifier)
    encoder.write(None)
    encoder.leave()  # AlgorithmIdentifier
    encoder.write(sk, asn1.Numbers.BitString)
    encoder.leave()
    return encoder.output()


def write_pem(filename, label, data):
    data = der_to_pem(data, label)
    with open(filename, 'wb') as f:
        f.write(data)


def der_to_pem(data, label=b'CERTIFICATE'):
    buf = BytesIO()
    buf.write(b"-----BEGIN ")
    buf.write(label)
    buf.write(b"-----\n")

    base64buf = BytesIO(base64.b64encode(data))
    line = base64buf.read(64)
    while line:
        buf.write(line)
        buf.write(b'\n')
        line = base64buf.read(64)

    buf.write(b"-----END ")
    buf.write(label)
    buf.write(b"-----\n")
    return buf.getvalue()


def get_alg_kind(algorithm):
    if 'sphincs' in algorithm:
        return 'sign'
    elif 'mqdss' in algorithm:
        return 'sign'


def set_up_algorithm(algorithm):
    if get_alg_kind(algorithm) == 'kem':
        set_up_kem_algorithm(algorithm)
    else:
        set_up_sign_algorithm(algorithm)


def set_up_sign_algorithm(algorithm):
    content = f"pub use pqcrypto::sign::{algorithm}::*;"
    with open('signutil/src/lib.rs', 'w') as f:
        f.write(content)


def set_up_kem_algorithm(algorithm):
    content = f"pub use pqcrypto::kem::{algorithm}::*;"
    with open('kemutil/src/kem.rs', 'w') as f:
        f.write(content)


def run_cargo_example(example, *args):
    subprocess.check_output(
        [*'cargo run --example'.split(), example, *args],
        cwd='signutil')


def get_keys():
    run_cargo_example('keygen')
    with open('signutil/publickey.bin', 'rb') as f:
        pk = f.read()
    with open('signutil/secretkey.bin', 'rb') as f:
        sk = f.read()
    return (pk, sk)


def print_date(time):
    return time.strftime("%y%m%d%H%M%SZ").encode()


def write_public_key(encoder, algorithm, pk):
    encoder.enter(asn1.Numbers.Sequence)  # SubjectPublicKeyInfo
    encoder.enter(asn1.Numbers.Sequence)  # AlgorithmIdentifier
    # FIXME: This should be parameterized
    oid = oids[algorithm]
    encoder.write(f'1.2.6.1.4.1.311.89.2.{16128 + oid}',
                  asn1.Numbers.ObjectIdentifier)
    encoder.write(None)
    encoder.leave()  # AlgorithmIdentifier
    encoder.write(pk, asn1.Numbers.BitString)
    encoder.leave()


def write_signature(encoder, algorithm, pk):
    tbsencoder = asn1.Encoder()
    tbsencoder.start()
    write_tbs_certificate(tbsencoder, algorithm, pk)
    tbscertificate_bytes = tbsencoder.output()
    with open('tbscertbytes.bin', 'wb') as f:
        f.write(tbscertificate_bytes)

    # Sign tbscertificate_bytes
    run_cargo_example('signer', 'secretkey.bin',
                      '../tbscertbytes.bin', '../tbs.sig')

    # Obtain signature
    with open('tbs.sig', 'rb') as f:
        sig = f.read()
    # Write bytes as bitstring
    encoder.write(sig, asn1.Numbers.BitString)


def write_signature_algorithm(encoder, algorithm):
    encoder.enter(asn1.Numbers.Sequence)  # enter algorithmidentifier
    # This should also be parameterized
    oid = oids[algorithm]
    encoder.write(f'1.2.6.1.4.1.311.89.2.{16128+oid}',
                  asn1.Numbers.ObjectIdentifier)
    encoder.write(None)  # Parameters
    encoder.leave()  # Leave AlgorithmIdentifier


def write_tbs_certificate(encoder, algorithm, pk, is_ca=False):
    #  TBSCertificate  ::=  SEQUENCE  {
    #      version         [0]  EXPLICIT Version DEFAULT v1,
    #      serialNumber         CertificateSerialNumber,
    #      signature            AlgorithmIdentifier,
    #      issuer               Name,
    #      validity             Validity,
    #      subject              Name,
    #      subjectPublicKeyInfo SubjectPublicKeyInfo,
    #      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
    #         -- If present, version MUST be v2 or v3
    #          subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
    #            -- If present, version MUST be v2 or v3
    #       extensions      [3]  EXPLICIT Extensions OPTIONAL
    #            -- If present, version MUST be v3
    #  }
    encoder.enter(asn1.Numbers.Sequence)
    encoder.enter(0, cls=asn1.Classes.Context)  # [0]
    encoder.write(2)  # version
    encoder.leave()  # [0]
    encoder.write(1)  # serialnumber

    write_signature_algorithm(encoder, algorithm)

    # ISSUER
    encoder.enter(asn1.Numbers.Sequence)  # Name
    encoder.enter(asn1.Numbers.Set)  # Set of attributes
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write('2.5.4.3', asn1.Numbers.ObjectIdentifier)  # commonName
    encoder.write('ThomCert', asn1.Numbers.PrintableString)
    encoder.leave()  # commonName
    encoder.leave()  # Set
    encoder.leave()  # Name

    # Validity
    now = datetime.utcnow()
    encoder.enter(asn1.Numbers.Sequence)  # Validity
    encoder.write(print_date(now), asn1.Numbers.UTCTime)
    encoder.write(print_date(now + timedelta(days=9000)), asn1.Numbers.UTCTime)
    encoder.leave()  # Validity

    # Subject
    encoder.enter(asn1.Numbers.Sequence)  # Name
    encoder.leave()  # empty Name: use subjectAltName (critical!)

    # SubjectPublicKeyInfo
    #    SubjectPublicKeyInfo  ::=  SEQUENCE  {
    #      algorithm            AlgorithmIdentifier,
    #      subjectPublicKey     BIT STRING  }
    write_public_key(encoder, algorithm, pk)

    # issuerUniqueId
    # skip?

    # Extensions
    encoder.enter(3, cls=asn1.Classes.Context)  # [3]
    encoder.enter(asn1.Numbers.Sequence)  # Extensions
    encoder.enter(asn1.Numbers.Sequence)  # Extension 1
    encoder.write('2.5.29.17', asn1.Numbers.ObjectIdentifier)
    encoder.write(True, asn1.Numbers.Boolean)  # Critical
    extvalue = asn1.Encoder()
    extvalue.start()
    extvalue.enter(asn1.Numbers.Sequence)  # Sequence of names
    extvalue._emit_tag(0x02, asn1.Types.Primitive, asn1.Classes.Context)
    extvalue._emit_length(len(b'localhost'))
    extvalue._emit(b'localhost')
    extvalue.leave()  # Sequence of names
    encoder.write(extvalue.output(), asn1.Numbers.OctetString)
    encoder.leave()  # Extension 1

    # Extended Key Usage
    if not is_ca:
        encoder.enter(asn1.Numbers.Sequence)  # Extension 2
        encoder.write('2.5.29.37', asn1.Numbers.ObjectIdentifier)
        encoder.write(False, asn1.Numbers.Boolean)  # Critical
        extvalue.start()
        extvalue.enter(asn1.Numbers.Sequence)  # Key Usages
        extvalue.write("1.3.6.1.5.5.7.3.1", asn1.Numbers.ObjectIdentifier)
        extvalue.leave()  # Key Usages
        encoder.write(extvalue.output(), asn1.Numbers.OctetString)
        encoder.leave()  # Extension 2

    encoder.enter(asn1.Numbers.Sequence)  # Extension CA
    encoder.write('2.5.29.19', asn1.Numbers.ObjectIdentifier)  # BasicConstr
    encoder.write(True, asn1.Numbers.Boolean)  # Critical
    extvalue.start()
    extvalue.enter(asn1.Numbers.Sequence)  # Constraints
    extvalue.write(is_ca, asn1.Numbers.Boolean)  # cA = True
    extvalue.write(10, asn1.Numbers.Integer)  # Max path length
    extvalue.leave()  # Constraints
    encoder.write(extvalue.output(), asn1.Numbers.OctetString)
    encoder.leave()  # BasicConstraints

    encoder.leave()  # Extensions
    encoder.leave()  # [3]

    # Done
    encoder.leave()  # Leave TBSCertificate SEQUENCE


def generate(pk_algorithm, sig_algorithm, filename, signing_key, ca=False):
    set_up_algorithm(pk_algorithm)

    (pk, sk) = get_keys()
    write_pem(f'{filename}.pub', b'PUBLIC KEY', public_key_der(algorithm, pk))
    write_pem(f'{filename}.key', b'PRIVATE KEY', 
              private_key_der(algorithm, sk))
    with open(f'{filename}.key.bin', 'wb') as f:
        f.write(sk)

    set_up_sign_algorithm(sig_algorithm)

    encoder = asn1.Encoder()
    encoder.start()

    # SEQUENCE of three things
    #   Certificate  ::=  SEQUENCE  {
    #       tbsCertificate       TBSCertificate,
    #       signatureAlgorithm   AlgorithmIdentifier,
    #       signatureValue       BIT STRING  }

    encoder.enter(asn1.Numbers.Sequence)  # Certificate
    write_tbs_certificate(encoder, algorithm, pk, is_ca=ca)
    # Write signature algorithm
    write_signature_algorithm(encoder, algorithm)
    write_signature(encoder, algorithm, pk)

    encoder.leave()  # Leave Certificate SEQUENCE

    with open(f'{filename}.crt.bin', 'wb') as f:
        f.write(encoder.output())
    write_pem(f'{filename}.crt', b'CERTIFICATE', encoder.output())


if __name__ == "__main__":
    for algorithm in oids.keys():
        print(f"Generating keys for {algorithm}")
        generate(algorithm, algorithm,
                 f"{algorithm}-ca", f"{algorithm}-ca.key.bin", ca=True)
        generate(algorithm, algorithm,
                 f"{algorithm}", f"{algorithm}-ca.key.bin", ca=False)
        with open(f"{algorithm}-chain.crt", 'wb') as f:
            with open(f"{algorithm}.crt", 'rb') as cert:
                f.write(cert.read())
            with open(f"{algorithm}-ca.crt", 'rb') as cert:
                f.write(cert.read())
