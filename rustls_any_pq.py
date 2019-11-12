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
    sphincs_id = f"SPHINCS_{hash}_{size.upper()}_{type.upper()}"
    print(rf"(SignatureScheme::{sphincs_id}, &signature::{sphincs_id}),")

for alg in other_sig_algorithms:
    print(rf"(SignatureScheme::{alg}, &signature::{alg}),")
