openssl x509 -req -in ../pki/reqs/localhost.req -CA ../pki/ca.crt -CAkey ../pki/private/ca.key -force_pubkey x25519.pub -out x25519.crt -extfile ../pki/safessl-easyrsa.cnf -extensions v3_req
