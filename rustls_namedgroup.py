from encoder import kems

kems = kems[1:]

for (i, kem) in enumerate(kems):
    print(f"       {kem.upper()} => {509+i},")


print("// namedgroup_to_alg")
for kem in kems:
    print(f"            NamedGroup::{kem.upper()} => Some(&ring::agreement::{kem.upper()}),")


print("// supported_groups")
for kem in kems:
    print(f"            NamedGroup::{kem.upper()},")

