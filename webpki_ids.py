from encoder import oids, sphincs_variants

for (hash, size, type) in sphincs_variants:
    index = f"sphincs{hash}{size}{type}"
    oid_offset = oids[index]
    if hash == "shake256":
        hash = "SHAKE_256"
    elif hash == "sha256":
        hash = "SHA_256"
    else:
        hash = hash.upper()
    oid_bytes = 0xFE00 + oid_offset
    sphincs_id = f"SPHINCS_{hash}_{size.upper()}_{type.upper()}_ID"
    print(rf"""
const {sphincs_id}: AlgorithmIdentifier = AlgorithmIdentifier {{
    asn1_id_value: b"\x06\x0B\x2B\x06\x01\x04\x01\x82\x37\x59\x02\x{oid_bytes>>8:02X}\x{oid_bytes&0xFF:02X}"
}};

/// SPHINCS signature
pub static {sphincs_id[:-3]}: SignatureAlgorithm = SignatureAlgorithm {{
    public_key_alg_id: {sphincs_id},
    signature_alg_id: {sphincs_id},
    verification_alg: &signature::{sphincs_id[:-3]},
}};

""")
