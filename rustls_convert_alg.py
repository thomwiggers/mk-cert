from encoder import oids, signs, camel_to_snake


for alg in signs:
    alg = camel_to_snake(alg).upper()
    print(rf"""{alg} => Ok(&webpki::{alg}),""")
