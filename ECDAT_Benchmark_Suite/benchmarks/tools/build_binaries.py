from pathlib import Path
import shutil, subprocess

ROOT=Path(__file__).resolve().parents[1]
src=ROOT/"binaries"/"source"
out=ROOT/"binaries"/"build"
out.mkdir(parents=True,exist_ok=True)
cc=shutil.which("gcc") or shutil.which("cc")
if not cc:
    raise SystemExit("gcc/cc unavailable")
subprocess.run([cc,str(src/"hello.c"),"-o",str(out/"B01_hello")],check=True)
subprocess.run([cc,str(src/"crypto_strings_only.c"),"-o",str(out/"B05_strings")],check=True)
try:
    subprocess.run([cc,str(src/"openssl_aes_gcm.c"),"-lcrypto","-o",str(out/"B02_openssl_aes_gcm")],check=True)
    strip=shutil.which("strip")
    if strip:
        shutil.copy2(out/"B02_openssl_aes_gcm",out/"B03_openssl_aes_gcm_stripped")
        subprocess.run([strip,str(out/"B03_openssl_aes_gcm_stripped")],check=True)
except subprocess.CalledProcessError:
    print("OpenSSL development libraries unavailable; B02/B03 not built")
