# Go-ipfix Tests

Go-ipfix uses fake certificates for unit test and integration test. The fake
certificates are generated manually and saved at [cert.go](certs.go). The
developers need to renew the certificates before they expire following the
steps below.

1. Generate a fake CA cert and save the content in `ca-cert.pem` to `FakeCACert`.
    ```shell
    openssl genrsa 2048 > ca-key.pem  
    openssl req -new -x509 -nodes -days 1000 -key ca-key.pem > ca-cert.pem
    ```
2. Generate the client certificate with RSA2048. Save the content in
   `client-key.pem` to `FakeKey` and `client-cert.pem`  to `FakeCert`.
   Repeat this step for `FakeClientKey` and `FakeClientCert`.
    ```shell
    openssl req -newkey rsa:2048 -days 1000 -nodes -keyout client-key.pem > client-req.pem
    echo subjectAltName = IP:127.0.0.1 > extfile.cnf
    openssl x509 -req -in client-req.pem -days 1000 -CA ca-cert.pem -CAkey ca-key.pem -set_serial 01 > client-cert.pem -extfile extfile.cnf
    ```
4. Generate the client certificate with ED25519. Save the content in
   `client-key.pem` to `FakeKey2` and `client-cert.pem`  to `FakeCert2`.
   ```shell
   openssl genpkey -algorithm ed25519 -out client-key.pem
   openssl req -new -sha256 -key client-key.pem -out client-req.pem
   echo subjectAltName = IP:127.0.0.1 > extfile.cnf
   openssl x509 -req -in client-req.pem -days 1000 -CA ca-cert.pem -CAkey ca-key.pem -set_serial 01 > client-cert.pem -extfile extfile.cnf
   ```
