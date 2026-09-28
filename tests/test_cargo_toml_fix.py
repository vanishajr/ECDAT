"""Regression tests: Cargo.toml manifest scanning (Fix 2).

A supported ecosystem must not raise AttributeError, and common Rust
crypto crates must resolve to findings.
"""

from ecdat.scanners.dependency.scanner import DependencyScanner


TOML = """[package]
name = "demo"
version = "0.1.0"
edition = "2021"

[dependencies]
ring = "0.17"
serde = "1.0"
aes-gcm = { version = "0.10", features = ["aes"] }

[dev-dependencies]
ed25519-dalek = "2"

[target.'cfg(unix)'.dependencies]
sha2 = "0.10"

[workspace.dependencies]
rsa = "0.9"
"""


def test_cargo_toml_no_crash_and_finds_crypto(tmp_path):
    target = tmp_path / "Cargo.toml"
    target.write_text(TOML)
    findings = DependencyScanner()._scan_file(target)
    libs = sorted(f.library for f in findings)
    assert libs == ["aes-gcm", "ed25519-dalek", "ring", "rsa", "sha2"]
    for f in findings:
        assert f.dependency_only
        assert f.location.file == str(target)


def test_cargo_toml_ignores_non_crypto_and_malformed(tmp_path):
    plain = tmp_path / "Cargo.toml"
    plain.write_text('[dependencies]\nserde = "1.0"\n')
    assert DependencyScanner()._scan_file(plain) == []
    broken = tmp_path / "sub" / "Cargo.toml"
    broken.parent.mkdir(parents=True)
    broken.write_text("[dependencies\nnot toml = =\n")
    assert DependencyScanner()._scan_file(broken) == []


def test_cargo_toml_git_and_path_specs(tmp_path):
    target = tmp_path / "Cargo.toml"
    target.write_text('[dependencies]\nring = { git = "https://github.com/briansmith/ring" }\n'
                      'aes = { path = "../aes" }\n')
    findings = DependencyScanner()._scan_file(target)
    assert sorted(f.library for f in findings) == ["aes", "ring"]
