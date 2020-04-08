from encoder import *

for alg in signs:
    alg = camel_to_snake(alg).upper()
    print(rf"   ({alg}, _) => SignatureScheme::{alg},")
