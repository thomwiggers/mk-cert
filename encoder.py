import asn1
from datetime import datetime, timedelta
import subprocess
import base64
from io import BytesIO
import re
import os
import resource
import time

import itertools

DEBUG = False

HOSTNAME = b'servername'

subenv = os.environ.copy()
if 'RUST_MIN_STACK' not in subenv:
    subenv["RUSTFLAGS"] = "-C target-cpu=native"
    subenv["RUST_MIN_STACK"] = str(20*1024*1024)


resource.setrlimit(resource.RLIMIT_STACK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))

def camel_to_snake(name):
  name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
  return re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()

signs = [
    "Dilithium2",
    "Dilithium3",
    "Dilithium4",
    "Falcon512",
    "Falcon1024",
    "MQDSS3148",
    "MQDSS3164",
    "RainbowIaClassic",
    "RainbowIaCyclic",
    "RainbowIaCyclicCompressed",
    "RainbowIIIcclassic",
    "RainbowIIIcCyclic",
    "RainbowIIIcCyclicCompressed",
    "RainbowVcClassic",
    "RainbowVcCyclic",
    "RainbowVcCyclicCompressed",
    "SphincsHaraka128fRobust",
    "SphincsHaraka128fSimple",
    "SphincsHaraka128sRobust",
    "SphincsHaraka128sSimple",
    "SphincsHaraka192fRobust",
    "SphincsHaraka192fSimple",
    "SphincsHaraka192sRobust",
    "SphincsHaraka192sSimple",
    "SphincsHaraka256fRobust",
    "SphincsHaraka256fSimple",
    "SphincsHaraka256sRobust",
    "SphincsHaraka256sSimple",
    "SphincsSha256128fRobust",
    "SphincsSha256128fSimple",
    "SphincsSha256128sRobust",
    "SphincsSha256128sSimple",
    "SphincsSha256192fRobust",
    "SphincsSha256192fSimple",
    "SphincsSha256192sRobust",
    "SphincsSha256192sSimple",
    "SphincsSha256256fRobust",
    "SphincsSha256256fSimple",
    "SphincsSha256256sRobust",
    "SphincsSha256256sSimple",
    "SphincsShake256128fRobust",
    "SphincsShake256128fSimple",
    "SphincsShake256128sRobust",
    "SphincsShake256128sSimple",
    "SphincsShake256192fRobust",
    "SphincsShake256192fSimple",
    "SphincsShake256192sRobust",
    "SphincsShake256192sSimple",
    "SphincsShake256256fRobust",
    "SphincsShake256256fSimple",
    "SphincsShake256256sRobust",
    "SphincsShake256256sSimple",
    "PicnicL1Fs",
    "PicnicL1Ur",
    "PicnicL3Fs",
    "PicnicL3Ur",
    "PicnicL5Fs",
    "PicnicL5Ur",
    "Picnic2L1Fs",
    "Picnic2L3Fs",
    "Picnic2L5Fs",
    "QTeslaPI",
    "QTeslaPIII",
    "XMSS",
]

kems = [
    # CSIDH
    "csidh",
    # kyber
    "kyber512",
    "kyber768",
    "kyber1024",
    # kyber90s
    "kyber51290s",
    "kyber76890s",
    "kyber102490s",
    # threebears
    "babybear",
    "babybearephem",
    "mamabear",
    "mamabearephem",
    "papabear",
    "papabearephem",
    # SABER
    "lightsaber",
    "saber",
    "firesaber",
    # leda
    "ledakemlt12",
    "ledakemlt32",
    "ledakemlt52",
    # newhope
    "newhope512cpa",
    "newhope512cca",
    "newhope1024cpa",
    "newhope1024cca",
    # NTRU
    "ntruhps2048509",
    "ntruhps2048677",
    "ntruhps4096821",
    "ntruhrss701",
    # Frodo
    "frodokem640aes",
    "frodokem640shake",
    "frodokem976aes",
    "frodokem976shake",
    "frodokem1344aes",
    "frodokem1344shake",
    # McEliece
    "mceliece348864",
    "mceliece348864f",
    "mceliece460896",
    "mceliece460896f",
    "mceliece6688128",
    "mceliece6688128f",
    "mceliece6960119",
    "mceliece6960119f",
    "mceliece8192128",
    "mceliece8192128f",
    # hqc
    "hqc1281cca2",
    "hqc1921cca2",
    "hqc1922cca2",
    "hqc2561cca2",
    "hqc2562cca2",
    "hqc2563cca2",
]

OQS_KEMS = [
    ("bikel1fo", "BikeL1Fo"),
    ("sikep434compressed", "SikeP434Compressed"),
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


oids = {var: i for (i, var) in enumerate(itertools.chain(signs, kems))}


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
    oid = oids[algorithm]
    encoder.write(f"1.2.6.1.4.1.311.89.2.{16128 + oid}", asn1.Numbers.ObjectIdentifier)
    #encoder.write(None)
    encoder.leave()  # AlgorithmIdentifier
    nestedencoder = asn1.Encoder()
    nestedencoder.start()
    nestedencoder.write(sk, asn1.Numbers.OctetString)
    encoder.write(nestedencoder.output(), asn1.Numbers.OctetString)
    encoder.leave()
    return encoder.output()


def write_pem(filename, label, data):
    data = der_to_pem(data, label)
    with open(filename, "wb") as f:
        f.write(data)


def der_to_pem(data, label=b"CERTIFICATE"):
    buf = BytesIO()
    buf.write(b"-----BEGIN ")
    buf.write(label)
    buf.write(b"-----\n")

    base64buf = BytesIO(base64.b64encode(data))
    line = base64buf.read(64)
    while line:
        buf.write(line)
        buf.write(b"\n")
        line = base64buf.read(64)

    buf.write(b"-----END ")
    buf.write(label)
    buf.write(b"-----\n")
    return buf.getvalue()


def set_up_algorithm(algorithm, type):
    if type == "kem":
        set_up_kem_algorithm(algorithm)
    else:
        set_up_sign_algorithm(algorithm)


def set_up_sign_algorithm(algorithm):
    if algorithm != "XMSS":
        content = f"pub use oqs::sig::Algorithm::{algorithm} as alg;"
        with open("signutil/src/lib.rs", "w") as f:
            f.write(content)


def set_up_kem_algorithm(algorithm):
    if algorithm == "csidh":
        content = f"pub use csidh_rust::*;"
    elif is_oqs_algorithm(algorithm):
        content = f"pub use oqs::kem::Algorithm::{get_oqs_algorithm(algorithm)} as thealgorithm;"
    else:
        content = f"pub use pqcrypto::kem::{algorithm}::*;"
    with open("kemutil/src/kem.rs", "w") as f:
        f.write(content)


def run_signutil(example, alg, *args):
    if alg == "XMSS":
        cwd = "xmss-rs"
    else:
        cwd = "signutil"

    print(f"Running 'cargo run --example {example} {' '.join(args)}' in {cwd}")
    subprocess.run(
        [*"cargo run --release --example".split(), example, *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        env=subenv,
    )


def get_keys(type, algorithm):
    if type == "kem":
        return get_kem_keys(algorithm)
    elif type == "sign":
        return get_sig_keys(algorithm)


def get_kem_keys(algorithm):
    if is_oqs_algorithm(algorithm):
        variant = "liboqs"
    else:
        variant = "pqclean"
    subprocess.run(
        ["cargo", "run", "--release", "--features", variant],
        cwd="kemutil",
        check=True,
        env=subenv,
        capture_output=True,
    )
    with open("kemutil/publickey.bin", "rb") as f:
        pk = f.read()
    with open("kemutil/secretkey.bin", "rb") as f:
        sk = f.read()
    return (pk, sk)


def get_sig_keys(alg):
    run_signutil("keygen", alg)
    if alg == "XMSS":
        with open("xmss-rs/publickey.bin", "rb") as f:
            pk = f.read()
        with open("xmss-rs/secretkey.bin", "rb") as f:
            sk = f.read()
    else:
        with open("signutil/publickey.bin", "rb") as f:
            pk = f.read()
        with open("signutil/secretkey.bin", "rb") as f:
            sk = f.read()
    return (pk, sk)


def print_date(time):
    return time.strftime("%y%m%d%H%M%SZ").encode()


def write_public_key(encoder, algorithm, pk):
    encoder.enter(asn1.Numbers.Sequence)  # SubjectPublicKeyInfo
    encoder.enter(asn1.Numbers.Sequence)  # AlgorithmIdentifier
    # FIXME: This should be parameterized
    oid = oids[algorithm]
    encoder.write(f"1.2.6.1.4.1.311.89.2.{16128 + oid}", asn1.Numbers.ObjectIdentifier)
    #encoder.write(None)
    encoder.leave()  # AlgorithmIdentifier
    encoder.write(pk, asn1.Numbers.BitString)
    encoder.leave()


def write_signature(encoder, algorithm, sign_algorithm, pk, signing_key, is_ca, pathlen):
    tbsencoder = asn1.Encoder()
    tbsencoder.start()
    write_tbs_certificate(tbsencoder, algorithm, sign_algorithm, pk, is_ca=is_ca, pathlen=pathlen)
    tbscertificate_bytes = tbsencoder.output()
    tbscertbytes_file = f"tbscertbytes_for{algorithm}_by_{signing_key[3:].lower()}.bin"
    tbssig_file = f"tbs_sig_for-{algorithm}-by-{signing_key[3:].lower()}.bin"
    with open(tbscertbytes_file, "wb") as f:
        f.write(tbscertificate_bytes)

    # Sign tbscertificate_bytes
    if DEBUG:
        time.sleep(2)
    run_signutil("signer", sign_algorithm, signing_key.lower(), f"../{tbscertbytes_file}", f"../{tbssig_file}")

    # Obtain signature
    with open(tbssig_file, "rb") as f:
        sig = f.read()

    # Write bytes as bitstring
    encoder.write(sig, asn1.Numbers.BitString)


def write_signature_algorithm(encoder, algorithm):
    encoder.enter(asn1.Numbers.Sequence)  # enter algorithmidentifier
    # This should also be parameterized
    oid = oids[algorithm]
    encoder.write(f"1.2.6.1.4.1.311.89.2.{16128+oid}", asn1.Numbers.ObjectIdentifier)
    #encoder.write(None)  # Parameters
    encoder.leave()  # Leave AlgorithmIdentifier


def write_tbs_certificate(encoder, algorithm, sign_algorithm, pk, is_ca=False, pathlen=4):
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
    encoder.write("2.5.4.3", asn1.Numbers.ObjectIdentifier)  # commonName
    encoder.write("ThomCert", asn1.Numbers.PrintableString)
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
        encoder.write("2.5.4.3", asn1.Numbers.ObjectIdentifier)  # commonName
        encoder.write("ThomCert", asn1.Numbers.PrintableString)
        encoder.leave()  # commonName
        encoder.leave()  # Set
    encoder.leave()  # empty Name: use subjectAltName (critical!)

    # SubjectPublicKeyInfo
    #    SubjectPublicKeyInfo  ::=  SEQUENCE  {
    #      algorithm            AlgorithmIdentifier,
    #      subjectPublicKey     BIT STRING  }
    # print(f"Written {len(pk)} bytes of pk")
    write_public_key(encoder, algorithm, pk)

    # issuerUniqueId
    # skip?

    # Extensions
    encoder.enter(3, cls=asn1.Classes.Context)  # [3]
    encoder.enter(asn1.Numbers.Sequence)  # Extensions
    extvalue = asn1.Encoder()
    if not is_ca:
        encoder.enter(asn1.Numbers.Sequence)  # Extension 1
        encoder.write("2.5.29.17", asn1.Numbers.ObjectIdentifier)
        encoder.write(True, asn1.Numbers.Boolean)  # Critical
        extvalue.start()
        extvalue.enter(asn1.Numbers.Sequence)  # Sequence of names
        extvalue._emit_tag(0x02, asn1.Types.Primitive, asn1.Classes.Context)
        extvalue._emit_length(len(HOSTNAME))
        extvalue._emit(HOSTNAME)
        extvalue.leave()  # Sequence of names
        encoder.write(extvalue.output(), asn1.Numbers.OctetString)
        encoder.leave()  # Extension 1

    # Extended Key Usage
    if not is_ca:
        encoder.enter(asn1.Numbers.Sequence)  # Extension 2
        encoder.write("2.5.29.37", asn1.Numbers.ObjectIdentifier)
        encoder.write(False, asn1.Numbers.Boolean)  # Critical
        extvalue.start()
        extvalue.enter(asn1.Numbers.Sequence)  # Key Usages
        extvalue.write("1.3.6.1.5.5.7.3.1", asn1.Numbers.ObjectIdentifier)
        extvalue.leave()  # Key Usages
        encoder.write(extvalue.output(), asn1.Numbers.OctetString)
        encoder.leave()  # Extension 2

    encoder.enter(asn1.Numbers.Sequence)  # Extension CA
    encoder.write("2.5.29.19", asn1.Numbers.ObjectIdentifier)  # BasicConstr
    encoder.write(True, asn1.Numbers.Boolean)  # Critical
    extvalue.start()
    extvalue.enter(asn1.Numbers.Sequence)  # Constraints
    extvalue.write(is_ca, asn1.Numbers.Boolean)  # cA = True
    if is_ca:
        extvalue.write(pathlen, asn1.Numbers.Integer)  # Max path length
    extvalue.leave()  # Constraints
    encoder.write(extvalue.output(), asn1.Numbers.OctetString)
    encoder.leave()  # BasicConstraints

    encoder.leave()  # Extensions
    encoder.leave()  # [3]

    # Done
    encoder.leave()  # Leave TBSCertificate SEQUENCE


def generate(pk_algorithm, sig_algorithm, filename, signing_key, type="sign", ca=False, pathlen=4):
    filename = filename.lower()
    set_up_algorithm(pk_algorithm, type)

    (pk, sk) = get_keys(type, pk_algorithm)
    write_pem(f"{filename}.pub", b"PUBLIC KEY", public_key_der(pk_algorithm, pk))
    write_pem(f"{filename}.key", b"PRIVATE KEY", private_key_der(pk_algorithm, sk))
    with open(f"{filename}.pub.bin", "wb") as publickeyfile:
        publickeyfile.write(pk)
    with open(f"{filename}.key.bin", "wb") as secretkeyfile:
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
    write_tbs_certificate(encoder, pk_algorithm, sig_algorithm, pk, is_ca=ca, pathlen=pathlen)
    # Write signature algorithm
    write_signature_algorithm(encoder, sig_algorithm)
    write_signature(encoder, pk_algorithm, sig_algorithm, pk, signing_key, is_ca=ca, pathlen=pathlen)

    encoder.leave()  # Leave Certificate SEQUENCE

    with open(f"{filename}.crt.bin", "wb") as file_:
        file_.write(encoder.output())
    write_pem(f"{filename}.crt", b"CERTIFICATE", encoder.output())


if __name__ == "__main__":
    root_sign_algorithm = os.environ.get("ROOT_SIGALG", "RainbowIaCyclic")
    intermediate_sign_algorithm = os.environ.get("INT_SIGALG", "Falcon512")
    leaf_sign_algorithm = os.environ.get("LEAF_SIGALG", "Falcon512")
    kex_alg = os.environ.get("KEX_ALG", "kyber512")

    assert kex_alg in kems
    assert intermediate_sign_algorithm in signs
    assert root_sign_algorithm in signs

    print(f"Generating keys for {leaf_sign_algorithm} signed by {intermediate_sign_algorithm} signed by {root_sign_algorithm}")
    generate(
        root_sign_algorithm,
        root_sign_algorithm,
        f"signing-ca",
        f"../signing-ca.key.bin",
        type="sign",
        ca=True,
    )
    generate(
        intermediate_sign_algorithm,
        root_sign_algorithm,
        f"signing-int",
        f"../signing-ca.key.bin",
        type="sign",
        ca=True,
        pathlen=1,
    )
    generate(
        leaf_sign_algorithm,
        intermediate_sign_algorithm,
        f"signing",
        f"../signing-int.key.bin",
        type="sign",
        ca=False,
    )

    with open("signing.chain.crt", "wb") as f:
        with open(f"signing.crt", "rb") as r:
            f.write(r.read())
        with open(f"signing-int.crt", "rb") as r:
            f.write(r.read())

    # KEM certs
    generate(
        root_sign_algorithm,
        root_sign_algorithm,
        f"kem-ca",
        f"../kem-ca.key.bin",
        type="sign",
        ca=True,
    )
    generate(
        intermediate_sign_algorithm,
        root_sign_algorithm,
        "kem-int",
        f"../kem-ca.key.bin",
        type="sign",
        ca=True,
        pathlen=1,
    )
    for kem_algorithm in kems:
        if kem_algorithm != kex_alg:
            continue
        print(f"Generating KEM cert for {kem_algorithm}")
        generate(
            kem_algorithm,
            intermediate_sign_algorithm,
            f"{kem_algorithm}",
            f"../kem-int.key.bin",
            type="kem",
        )

        with open(f"{kem_algorithm}.chain.crt", "wb") as file_:
            with open(f"{kem_algorithm}.crt", "rb") as r:
                file_.write(r.read())
            with open(f"kem-int.crt", "rb") as r:
                file_.write(r.read())
