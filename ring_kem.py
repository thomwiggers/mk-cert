from encoder import *

kems = kems[1:]

for kem in kems:
    if is_oqs_algorithm(kem):
        oqs_alg = get_oqs_algorithm(kem)
        print(f"oqs_kem_implementation!({kem}, {oqs_alg}, {kem.upper()});")
    else:
        print(f"pqclean_kem_implementation!({kem}, {kem.title()}, {kem.upper()});")


print("// algorithm_to_id")
for (i, kem) in enumerate(kems):
    print(f"else if alg == &{kem.upper()} {{")
    print(f"    {101+i}")
    print("}")


print("// ring/src/agreement.rs")
for kem in kems:
    print(f"    {kem.upper()},")
