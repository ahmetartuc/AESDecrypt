# AESDecrypt (Grafana)

**AESDecrypt (Grafana)** is a simple Python tool for **decrypting and encrypting sensitive data**, such as passwords and secret keys used in Grafana configurations. It leverages the `cryptography` library to perform AES encryption and decryption operations.

---

## Requirements

- **Python 3.x**
- **`cryptography` library**: Install it following command:
  ```bash
  pip3 install cryptography

## Example Output
[*] grafanaIni_secretKey= SW2YcwTIb9zpOOhoPsMm

[*] DataSourcePassword= anBneWFNQ2z+IDGhz3a7wxaqjimuglSXTeMvhbvsveZwVzreNJSw+hsV4w==  # change this

[*] plainText= SuperSecureP@ssw0rd

[*] grafanaIni_secretKey= SW2YcwTIb9zpOOhoPsMm

[*] PlainText= jas502n

[*] EncodePassword= 5FLHjXc7dqvKoIc4JFt1i2iCYPxGwBJn3CJbv8GSRw==
