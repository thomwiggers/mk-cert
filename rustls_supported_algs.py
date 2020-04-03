from encoder import oids, sphincs_variants, other_sig_algorithms

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
    sphincs_id = f"SPHINCS_{hash}_{size.upper()}_{type.upper()}"
    print(rf"""&webpki::{sphincs_id},""")

for alg in other_sig_algorithms:
    print(rf"""&webpki::{alg},""")