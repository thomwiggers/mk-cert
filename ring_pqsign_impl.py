from encoder import oids, signs, camel_to_snake

for alg in signs:
    oid_offset = oids[alg]
    oid_bytes = 0xFE00 + oid_offset
    print(f"pqsig_scheme!({camel_to_snake(alg).upper()}, {alg});")
