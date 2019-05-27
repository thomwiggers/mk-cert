from encoder import oids, sphincs_variants

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
    print(f"    {sphincs_id},")
