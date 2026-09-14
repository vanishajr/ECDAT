from __future__ import annotations

import gc
import json
import statistics
import time
import tracemalloc
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import pytest

from ecdat import create_discovery_engine, SourceScanner, DependencyScanner, ConfigScanner, CertificateScanner
from ecdat.scanners.base import normalize_finding
from ecdat.scanners.source import PythonASTScanner
from ecdat.scanners.dependency import DependencyScanner
from ecdat.scanners.config.nginx_scanner import NginxScanner
from ecdat.scanners.config.apache_scanner import ApacheScanner
from ecdat.scanners.certificate.pem_scanner import PEMScanner


@dataclass
class BenchmarkResult:
    scanner_name: str
    fixture_name: str
    iterations: int
    times: list[float] = field(default_factory=list)
    memory_usage: list[float] = field(default_factory=list)
    finding_counts: list[int] = field(default_factory=list)

    @property
    def mean_time(self) -> float:
        return statistics.mean(self.times) if self.times else 0.0

    @property
    def median_time(self) -> float:
        return statistics.median(self.times) if self.times else 0.0

    @property
    def stdev_time(self) -> float:
        return statistics.stdev(self.times) if len(self.times) > 1 else 0.0

    @property
    def min_time(self) -> float:
        return min(self.times) if self.times else 0.0

    @property
    def max_time(self) -> float:
        return max(self.times) if self.times else 0.0

    @property
    def mean_memory_mb(self) -> float:
        return statistics.mean(self.memory_usage) if self.memory_usage else 0.0

    @property
    def mean_findings(self) -> float:
        return statistics.mean(self.finding_counts) if self.finding_counts else 0.0


class BenchmarkRunner:
    def __init__(self, iterations: int = 10) -> None:
        self.iterations = iterations
        self.results: list[BenchmarkResult] = []

    def run_scanner_benchmark(
        self,
        scanner,
        fixture_path: Path,
        scanner_name: str,
        fixture_name: str
    ) -> BenchmarkResult:
        result = BenchmarkResult(scanner_name=scanner_name, fixture_name=fixture_name, iterations=self.iterations)

        for _ in range(self.iterations):
            gc.collect()
            tracemalloc.start()

            start_time = time.perf_counter()
            findings = scanner.scan(fixture_path)
            end_time = time.perf_counter()

            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            elapsed = end_time - start_time
            result.times.append(elapsed)
            result.memory_usage.append(peak / (1024 * 1024))
            result.finding_counts.append(len(findings))

        self.results.append(result)
        return result

    def run_discovery_engine_benchmark(
        self,
        target_dir: Path,
        scanner_names: list[str],
        name: str
    ) -> BenchmarkResult:
        result = BenchmarkResult(scanner_name="DiscoveryEngine", fixture_name=name, iterations=self.iterations)

        for _ in range(self.iterations):
            gc.collect()
            tracemalloc.start()

            engine = create_discovery_engine(scanner_names)

            start_time = time.perf_counter()
            cir = engine.scan_and_emit_cir(target_dir, target_name=name)
            end_time = time.perf_counter()

            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            elapsed = end_time - start_time
            result.times.append(elapsed)
            result.memory_usage.append(peak / (1024 * 1024))
            result.finding_counts.append(cir.stats.asset_count)

        self.results.append(result)
        return result

    def print_results(self) -> None:
        print("\n" + "=" * 80)
        print("BENCHMARK RESULTS")
        print("=" * 80)

        for result in self.results:
            print(f"\nScanner: {result.scanner_name} | Fixture: {result.fixture_name}")
            print(f"  Iterations: {result.iterations}")
            print(f"  Time (mean): {result.mean_time*1000:.2f} ms")
            print(f"  Time (median): {result.median_time*1000:.2f} ms")
            print(f"  Time (stdev): {result.stdev_time*1000:.2f} ms")
            print(f"  Time (min/max): {result.min_time*1000:.2f} / {result.max_time*1000:.2f} ms")
            print(f"  Memory (mean): {result.mean_memory_mb:.2f} MB")
            print(f"  Findings (mean): {result.mean_findings:.1f}")

    def export_json(self, output_path: Path) -> None:
        data = []
        for result in self.results:
            data.append({
                "scanner": result.scanner_name,
                "fixture": result.fixture_name,
                "iterations": result.iterations,
                "mean_time_ms": result.mean_time * 1000,
                "median_time_ms": result.median_time * 1000,
                "stdev_time_ms": result.stdev_time * 1000,
                "min_time_ms": result.min_time * 1000,
                "max_time_ms": result.max_time * 1000,
                "mean_memory_mb": result.mean_memory_mb,
                "mean_findings": result.mean_findings,
                "raw_times": result.times,
                "raw_memory": result.memory_usage,
                "raw_findings": result.finding_counts,
            })
        output_path.write_text(json.dumps(data, indent=2))


def generate_large_source_fixture(target_dir: Path, num_files: int = 100, lines_per_file: int = 1000) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)

    template = """
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_aes_gcm(key: bytes, nonce: bytes, data: bytes):
    cipher = AESGCM(key)
    return cipher.encrypt(nonce, data, None)

def decrypt_aes_gcm(key: bytes, nonce: bytes, data: bytes):
    cipher = AESGCM(key)
    return cipher.decrypt(nonce, data, None)

def generate_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def rsa_encrypt(public_key, data: bytes):
    return public_key.encrypt(data, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def ecdh_exchange(private_key, peer_public_key):
    return private_key.exchange(ec.ECDH(), peer_public_key)

def sign_ecdsa(private_key, data: bytes):
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

def derive_pbkdf2(password: bytes, salt: bytes):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return kdf.derive(password)

def derive_hkdf(ikm: bytes, salt: bytes, info: bytes):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    return hkdf.derive(ikm)

def hash_sha256(data: bytes):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

# More crypto operations
def encrypt_aes_cbc(key: bytes, iv: bytes, data: bytes):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def encrypt_chacha20(key: bytes, nonce: bytes, data: bytes):
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    cipher = ChaCha20Poly1305(key)
    return cipher.encrypt(nonce, data, None)
"""

    for i in range(num_files):
        content = template * (lines_per_file // 50)
        (target_dir / f"crypto_module_{i}.py").write_text(content)


class TestBenchmarks:
    @pytest.fixture
    def runner(self):
        return BenchmarkRunner(iterations=5)

    @pytest.fixture
    def fixtures_dir(self):
        return Path(__file__).parent.parent / "tests" / "fixtures"

    @pytest.fixture
    def temp_dir(self, tmp_path):
        return tmp_path

    def test_source_scanner_benchmark(self, runner, fixtures_dir, temp_dir):
        scanner = SourceScanner()

        result = runner.run_scanner_benchmark(
            scanner,
            fixtures_dir / "source" / "aes_gcm.py",
            "SourceScanner",
            "aes_gcm.py"
        )
        assert result.mean_time < 1.0

    def test_source_scanner_large_project(self, runner, temp_dir):
        scanner = SourceScanner()
        large_dir = temp_dir / "large_project"
        generate_large_source_fixture(large_dir, num_files=50, lines_per_file=500)

        result = runner.run_scanner_benchmark(
            scanner,
            large_dir,
            "SourceScanner",
            "large_project_50_files"
        )
        print(f"Large project scan time: {result.mean_time:.3f}s")
        assert result.mean_time < 60.0

    def test_python_ast_scanner_benchmark(self, runner, fixtures_dir):
        scanner = PythonASTScanner()

        result = runner.run_scanner_benchmark(
            scanner,
            fixtures_dir / "source" / "aes_gcm.py",
            "PythonASTScanner",
            "aes_gcm.py"
        )
        assert result.mean_time < 1.0

    def test_dependency_scanner_benchmark(self, runner, fixtures_dir):
        scanner = DependencyScanner()

        result = runner.run_scanner_benchmark(
            scanner,
            fixtures_dir / "source" / "package.json",
            "DependencyScanner",
            "package.json"
        )
        assert result.mean_time < 1.0

    def test_config_scanner_benchmark(self, runner, fixtures_dir):
        scanner = ConfigScanner()

        result = runner.run_scanner_benchmark(
            scanner,
            fixtures_dir / "config",
            "ConfigScanner",
            "nginx_apache_envoy"
        )
        assert result.mean_time < 2.0

    def test_certificate_scanner_benchmark(self, runner, fixtures_dir):
        scanner = CertificateScanner()

        result = runner.run_scanner_benchmark(
            scanner,
            fixtures_dir / "certificate" / "test_cert.pem",
            "CertificateScanner",
            "test_cert.pem"
        )
        assert result.mean_time < 1.0

    def test_discovery_engine_benchmark(self, runner, temp_dir):
        test_dir = temp_dir / "bench_project"
        test_dir.mkdir()

        (test_dir / "main.py").write_text("""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
""")

        (test_dir / "requirements.txt").write_text("cryptography>=42.0\n")

        (test_dir / "nginx.conf").write_text("""
server {
    listen 443 ssl;
    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305;
}
""")

        result = runner.run_discovery_engine_benchmark(
            test_dir,
            ["source", "dependency", "config"],
            "small_project"
        )
        assert result.mean_time < 5.0

    def test_discovery_engine_large_project(self, runner, temp_dir):
        large_dir = temp_dir / "large_bench_project"
        generate_large_source_fixture(large_dir, num_files=100, lines_per_file=1000)

        (large_dir / "requirements.txt").write_text("cryptography>=42.0\nrequests\npyjwt\n")
        (large_dir / "nginx.conf").write_text("server { listen 443 ssl; ssl_protocols TLSv1.2 TLSv1.3; }")

        result = runner.run_discovery_engine_benchmark(
            large_dir,
            ["source", "dependency", "config"],
            "large_project_100_files"
        )
        print(f"Large project discovery time: {result.mean_time:.3f}s")
        assert result.mean_time < 60.0


if __name__ == "__main__":
    pytest.main(["-v", "--tb=short", __file__])