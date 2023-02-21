from algorithms import signs, kems, nikes
import subprocess
import sys

subprocess.run("docker build -t mkcert-benchmarker .".split(), check=True, stdout=sys.stderr)

for _, algorithm in kems:
    subprocess.run(f"docker run --rm mkcert-benchmarker kem {algorithm}".split(), check=True)

for _, algorithm in signs:
    subprocess.run(f"docker run --rm mkcert-benchmarker sign {algorithm}".split(), check=True)

# for algorithm in nikes:
#     subprocess.run(f"docker run --rm mkcert-benchmarker csidh {algorithm}".split(), check=True)

