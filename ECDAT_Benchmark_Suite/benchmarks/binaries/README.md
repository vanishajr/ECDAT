# Binary corpus

Build reproducibly into `benchmarks/binaries/build/`.

Recommended variants:

- B01 hello-world
- B02 dynamic OpenSSL AES-GCM
- B03 stripped B02
- B04 static OpenSSL variant where supported
- B05 crypto-looking strings only
- B06 constant/OID fixture
- B07 packed/suspected fixture where available
- B08 RSA OID/symbol fixture

Do not silently skip unavailable tools. Record LIEF/YARA/capa/FLOSS/Ghidra status.
