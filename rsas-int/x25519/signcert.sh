openssl x509 -req -in ../pki/reqs/servername.req -CA ../pki/ca.crt -CAkey ../pki/private/ca.key -force_pubkey x25519.pub -out x25519.crt -extfile ../pki/safessl-easyrsa.cnf -extensions v3_req -days 10000

openssl x509 -in x25519.crt -out x25519.chain.crt
openssl x509 -in ../pki/ca.crt >> x25519.chain.crt
