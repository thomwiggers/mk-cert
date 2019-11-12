from encoder import oids, sphincs_variants, other_sig_algorithms

for (hash, size, type) in sphincs_variants:
    index = f"sphincs{hash}{size}{type}"
    oid_offset = oids[index]
    if hash == "shake256":
        hash_id = "SHAKE_256"
    elif hash == "sha256":
        hash_id = "SHA_256"
    else:
        hash_id = hash.upper()
    oid_bytes = 0xFE00 + oid_offset
    sphincs_id = f"SPHINCS_{hash_id}_{size.upper()}_{type.upper()}"
    ns = f"sphincs{hash}{size}{type}"
    print(f"pqsig_scheme!({sphincs_id}, {ns});")

for alg in other_sig_algorithms:
    oid_offset = oids[alg]
    oid_bytes = 0xFE00 + oid_offset
    ns = alg.lower().replace('_', '')
    print(f"pqsig_scheme!({alg}, {ns});")
