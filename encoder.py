import asn1
from datetime import datetime, timedelta
import subprocess

import itertools

oids = {
    var: i
    for (i, var) in enumerate(
        f"sphincs{hash}{size}{type}"
        for (hash, size, type)
        in itertools.product(
            ['sha256', 'shake256', 'haraka'],
            ['128s', '128f', '192s', '192f', '256s', '256f'],
            ['simple', 'robust']))
}


def set_up_algorithm(algorithm):
    content = f"pub use pqcrypto::sign::{algorithm}::*;"
    with open('signutil/src/lib.rs', 'w') as f:
        f.write(content)


def run_cargo_example(example, *args):
    subprocess.check_call(
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


def write_tbs_certificate(encoder, algorithm, pk):
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
    encoder.write(2)  # version
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

    # issuerUniqueId
    # skip?

    # Extensions
    encoder.enter(asn1.Numbers.Sequence)  # Extensions
    encoder.enter(asn1.Numbers.Sequence)  # Extension 1
    encoder.write('2.5.29.17', asn1.Numbers.ObjectIdentifier)
    encoder.write(True, asn1.Numbers.Boolean)  # Critical
    encoder.enter(asn1.Numbers.Sequence)  # Sequence of names
    encoder.write(b'localhost', asn1.Numbers.IA5String)
    encoder.leave()  # Sequence of names
    encoder.leave()  # Extension 1

    # Extended Key Usage
    encoder.enter(asn1.Numbers.Sequence)  # Extension 2
    encoder.write('2.5.29.37', asn1.Numbers.ObjectIdentifier)
    encoder.write(False, asn1.Numbers.Boolean)  # Critical
    encoder.enter(asn1.Numbers.Sequence)  # Key Usages
    encoder.write("1.3.6.1.5.5.7.3.1", asn1.Numbers.ObjectIdentifier)
    encoder.leave()  # Key Usages
    encoder.leave()  # Extension 2

    encoder.leave()  # Extensions

    # Done
    encoder.leave()  # Leave TBSCertificate SEQUENCE


def generate(algorithm):
    set_up_algorithm(algorithm)

    (pk, sk) = get_keys()

    encoder = asn1.Encoder()
    encoder.start()

    # SEQUENCE of three things
    #   Certificate  ::=  SEQUENCE  {
    #       tbsCertificate       TBSCertificate,
    #       signatureAlgorithm   AlgorithmIdentifier,
    #       signatureValue       BIT STRING  }

    encoder.enter(asn1.Numbers.Sequence)  # Certificate
    write_tbs_certificate(encoder, algorithm, pk)
    # Write signature algorithm
    write_signature_algorithm(encoder, algorithm)
    write_signature(encoder, algorithm, pk)

    encoder.leave()  # Leave Certificate SEQUENCE

    with open(f'{algorithm}-cert.der', 'wb') as f:
        f.write(encoder.output())
    with open(f'{algorithm}.pub', 'wb') as f:
        f.write(sk)
    with open(f'{algorithm}.key', 'wb') as f:
        f.write(sk)


if __name__ == "__main__":
    for name in oids.keys():
        generate(name)
