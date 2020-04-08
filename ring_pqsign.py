from encoder import *


print("pub enum AlgorithmID {")
for alg in signs:
    snakename = camel_to_snake(alg).upper()
    index = alg
    oid_offset = oids[index]
    oid_bytes = 0xFE00 + oid_offset
    print(f"    {snakename} = 0x{oid_bytes:X},")
print("}")
