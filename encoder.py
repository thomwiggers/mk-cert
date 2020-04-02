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
other_sig_algorithms = [
    "MQDSS_48",
    "MQDSS_64",
    "QTESLA_P_III",
    "QTESLA_P_I",
    "FALCON_512",
    "FALCON_1024",
]

signs = [f"sphincs{hash}{size}{type}"
         for (hash, size, type)
         in sphincs_variants] + other_sig_algorithms

kems = [
    # CSIDH
    "csidh",
    # kyber
    "kyber512", "kyber768", "kyber1024",
    # kyber90s
    "kyber51290s", "kyber76890s", "kyber102490s",
    # threebears
    "babybear", "mamabear", "papabear",
    # SABER
    "lightsaber", "saber", "firesaber",
    # leda
    "ledakemlt12", "ledakemlt32", "ledakemlt52",
    # newhope
    "newhope512cpa", "newhope512cca", "newhope1024cpa", "newhope1024cca",
    # NTRU
    "ntruhps2048509", "ntruhps2048677", "ntruhps4096821", "ntruhrss701",
    # Frodo
    "frodokem640aes", "frodokem640shake", "frodokem976aes", "frodokem976shake",
    "frodokem1344aes", "frodokem1344shake",
]

OQS_KEMS = [
    ('sikep434compresed', 'SikeP434Compressed'),
    ('sikep434compresed', 'SikeP434Compressed'),
]

kems.extend((kem for (kem, _) in OQS_KEMS))


def is_oqs_algorithm(algorithm):
    for (kem, _) in OQS_KEMS:
        if kem == algorithm:
            return True
    return False


def get_oqs_algorithm(algorithm):
    for (kem, alg) in OQS_KEMS:
        if kem == algorithm:
            return alg
    return False


oids = {
    var: i
    for (i, var) in [
        *enumerate(itertools.chain(signs)),
        *[(i+100, var) for (i, var) in enumerate(kems)]
    ]
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
    encoder.write(sk, asn1.Numbers.OctetString)
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


def set_up_algorithm(algorithm, type):
    if type == 'kem':
        set_up_kem_algorithm(algorithm)
    else:
        set_up_sign_algorithm(algorithm)


def set_up_sign_algorithm(algorithm):
    content = f"pub use pqcrypto::sign::{algorithm}::*;"
    with open('signutil/src/lib.rs', 'w') as f:
        f.write(content)



def set_up_kem_algorithm(algorithm):
    if algorithm == 'csidh':
        content = f"pub use csidh_rust::*;"
    elif is_oqs_algorithm(algorithm):
        content = f"pub use oqs::kem::Algorithm::{get_oqs_algorithm(algorithm)} as thealgorithm;"
    else:
        content = f"pub use pqcrypto::kem::{algorithm}::*;"
    with open('kemutil/src/kem.rs', 'w') as f:
        f.write(content)


def run_signutil(example, *args):
    print(f"Running 'cargo run --example {example} {' '.join(args)}'")
    subprocess.check_output(
        [*'cargo run --example'.split(), example, *args],
        cwd='signutil')


def get_keys(type, algorithm):
    if type == "kem":
        return get_kem_keys(algorithm)
    elif type == "sign":
        return get_sig_keys()


def get_kem_keys(algorithm):
    if is_oqs_algorithm(algorithm):
        variant = "liboqs"
    else:
        variant = "pqclean"
    subprocess.check_output(
        ["cargo", "run", "--features", variant],
        cwd='kemutil')
    with open('kemutil/publickey.bin', 'rb') as f:
        pk = f.read()
    with open('kemutil/secretkey.bin', 'rb') as f:
        sk = f.read()
    return (pk, sk)


def get_sig_keys():
    run_signutil('keygen')
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


def write_signature(encoder, algorithm, sign_algorithm, pk, signing_key):
    tbsencoder = asn1.Encoder()
    tbsencoder.start()
    write_tbs_certificate(tbsencoder, algorithm, sign_algorithm, pk)
    tbscertificate_bytes = tbsencoder.output()
    with open('tbscertbytes.bin', 'wb') as f:
        f.write(tbscertificate_bytes)

    # Sign tbscertificate_bytes
    run_signutil('signer', signing_key,
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


def write_tbs_certificate(encoder, algorithm, sign_algorithm, pk, is_ca=False):
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

    write_signature_algorithm(encoder, sign_algorithm)

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
    if is_ca:
        encoder.enter(asn1.Numbers.Set)  # Set of attributes
        encoder.enter(asn1.Numbers.Sequence)
        encoder.write('2.5.4.3', asn1.Numbers.ObjectIdentifier)  # commonName
        encoder.write('ThomCert', asn1.Numbers.PrintableString)
        encoder.leave()  # commonName
        encoder.leave()  # Set
    encoder.leave()  # empty Name: use subjectAltName (critical!)

    # SubjectPublicKeyInfo
    #    SubjectPublicKeyInfo  ::=  SEQUENCE  {
    #      algorithm            AlgorithmIdentifier,
    #      subjectPublicKey     BIT STRING  }
    print(f"Written {len(pk)} bytes of pk")
    write_public_key(encoder, algorithm, pk)

    # issuerUniqueId
    # skip?

    # Extensions
    encoder.enter(3, cls=asn1.Classes.Context)  # [3]
    encoder.enter(asn1.Numbers.Sequence)  # Extensions
    extvalue = asn1.Encoder()
    if not is_ca:
        encoder.enter(asn1.Numbers.Sequence)  # Extension 1
        encoder.write('2.5.29.17', asn1.Numbers.ObjectIdentifier)
        encoder.write(True, asn1.Numbers.Boolean)  # Critical
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
    extvalue.write(4, asn1.Numbers.Integer)  # Max path length
    extvalue.leave()  # Constraints
    encoder.write(extvalue.output(), asn1.Numbers.OctetString)
    encoder.leave()  # BasicConstraints

    encoder.leave()  # Extensions
    encoder.leave()  # [3]

    # Done
    encoder.leave()  # Leave TBSCertificate SEQUENCE


def generate(pk_algorithm, sig_algorithm, filename,
             signing_key, type='sign', ca=False):
    set_up_algorithm(pk_algorithm, type)

    (pk, sk) = get_keys(type, pk_algorithm)
    write_pem(f'{filename}.pub', b'PUBLIC KEY', public_key_der(algorithm, pk))
    write_pem(f'{filename}.key', b'PRIVATE KEY',
              private_key_der(algorithm, sk))
    with open(f'{filename}.pub.bin', 'wb') as publickeyfile:
        publickeyfile.write(pk)
    with open(f'{filename}.key.bin', 'wb') as secretkeyfile:
        secretkeyfile.write(sk)

    set_up_sign_algorithm(sig_algorithm)

    encoder = asn1.Encoder()
    encoder.start()

    # SEQUENCE of three things
    #   Certificate  ::=  SEQUENCE  {
    #       tbsCertificate       TBSCertificate,
    #       signatureAlgorithm   AlgorithmIdentifier,
    #       signatureValue       BIT STRING  }

    encoder.enter(asn1.Numbers.Sequence)  # Certificate
    write_tbs_certificate(encoder, pk_algorithm, sig_algorithm, pk, is_ca=ca)
    # Write signature algorithm
    write_signature_algorithm(encoder, sig_algorithm)
    write_signature(encoder, pk_algorithm, sig_algorithm, pk, signing_key)

    encoder.leave()  # Leave Certificate SEQUENCE

    with open(f'{filename}.crt.bin', 'wb') as file_:
        file_.write(encoder.output())
    write_pem(f'{filename}.crt', b'CERTIFICATE', encoder.output())


if __name__ == "__main__":
    for algorithm in signs:
        if algorithm != 'sphincsshake256128ssimple':
            continue
        print(f"Generating keys for {algorithm}")
        generate(algorithm, algorithm,
                 f"{algorithm}-ca", f"../{algorithm}-ca.key.bin",
                 type='sign', ca=True)
        generate(algorithm, algorithm,
                 f"{algorithm}", f"../{algorithm}-ca.key.bin",
                 type='sign', ca=False)

    # KEM certs
    sign_algorithm = "sphincsshake256128ssimple"
    generate(sign_algorithm, sign_algorithm,
             f"kem-ca", f"../kem-ca.key.bin",
             type='sign', ca=True)
    for kem_algorithm in kems:
        print(f"Generating KEM cert for {kem_algorithm}")
        generate(kem_algorithm, sign_algorithm, f"{kem_algorithm}",
                 f"../kem-ca.key.bin", type="kem")
