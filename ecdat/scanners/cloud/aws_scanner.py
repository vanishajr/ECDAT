from __future__ import annotations

from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, create_evidence_signal, normalize_finding
from ecdat.core.cir_models import UsageState, Location, Implementation, Context, Exposure
from ecdat.core.signature_registry import normalize_algorithm, get_category, is_library_only


class AWSScanner(Scanner[ScannerFinding]):
    name = "cloud-aws"
    version = "0.1.0"

    def __init__(self) -> None:
        self._boto3_available = self._check_boto3()
        self._session = None

    def _check_boto3(self) -> bool:
        try:
            import boto3
            return True
        except ImportError:
            return False

    def is_available(self) -> bool:
        if not self._boto3_available:
            return False

        try:
            import boto3
            self._session = boto3.Session()
            sts = self._session.client("sts")
            sts.get_caller_identity()
            return True
        except Exception:
            return False

    def get_tool_version(self) -> str:
        try:
            import boto3
            return f"aws-boto3-{boto3.__version__}"
        except Exception:
            return "aws-unknown"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        if not self.is_available():
            return []

        findings: list[ScannerFinding] = []

        region = kwargs.get("region", "us-east-1")
        if self._session:
            self._session = self._session._session_factory(region_name=region) if hasattr(self._session, '_session_factory') else self._session
        else:
            import boto3
            self._session = boto3.Session(region_name=region)

        findings.extend(self._scan_kms(region))
        findings.extend(self._scan_acm(region))
        findings.extend(self._scan_elb(region))
        findings.extend(self._scan_alb(region))

        normalized = [normalize_finding(f) for f in findings]
        return normalized

    def _scan_kms(self, region: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            kms = self._session.client("kms", region_name=region)
            paginator = kms.get_paginator("list_keys")

            for page in paginator.paginate():
                for key in page.get("Keys", []):
                    key_id = key["KeyId"]
                    try:
                        desc = kms.describe_key(KeyId=key_id)
                        key_metadata = desc["KeyMetadata"]

                        key_spec = key_metadata.get("KeySpec", key_metadata.get("KeyManager", "UNKNOWN"))
                        key_usage = key_metadata.get("KeyUsage", "ENCRYPT_DECRYPT")
                        origin = key_metadata.get("Origin", "AWS_KMS")
                        key_manager = key_metadata.get("KeyManager", "CUSTOMER")

                        canonical, original = self._map_kms_key_spec(key_spec)

                        findings.append(ScannerFinding(
                            canonical=canonical,
                            original=original,
                            key_size=self._get_kms_key_size(key_spec),
                            usage_state=UsageState.PROVIDED_ONLY,
                            confidence=0.8,
                            evidence=[create_evidence_signal(
                                tool="cloud-aws",
                                detail=f"KMS Key: {key_id}, Spec={key_spec}, Usage={key_usage}, Origin={origin}, Manager={key_manager}",
                                confidence=0.8,
                                snippet=f"KMS Key ID: {key_id}",
                            )],
                            location=Location(uri=f"aws:kms:{region}:{key_id}"),
                            implementation=Implementation(library="AWS KMS", provider="aws", api="KMS"),
                            context=Context(exposure=Exposure.CLOUD, environment=region),
                        ))
                    except Exception:
                        continue
        except Exception:
            pass

        return findings

    def _scan_acm(self, region: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            acm = self._session.client("acm", region_name=region)
            paginator = acm.get_paginator("list_certificates")

            for page in paginator.paginate():
                for cert_summary in page.get("CertificateSummaryList", []):
                    arn = cert_summary.get("CertificateArn", "")
                    domain = cert_summary.get("DomainName", "")
                    status = cert_summary.get("Status", "")
                    key_algorithm = cert_summary.get("KeyAlgorithm", "")
                    key_usages = cert_summary.get("KeyUsages", [])
                    extended_key_usages = cert_summary.get("ExtendedKeyUsages", [])

                    canonical, original = normalize_algorithm(key_algorithm) if key_algorithm else ("X.509", "ACM Certificate")

                    findings.append(ScannerFinding(
                        canonical=canonical,
                        original=original,
                        key_size=self._get_acm_key_size(key_algorithm),
                        usage_state=UsageState.PROVIDED_ONLY,
                        confidence=0.8,
                        evidence=[create_evidence_signal(
                            tool="cloud-aws",
                            detail=f"ACM Certificate: {domain}, Status={status}, KeyAlgorithm={key_algorithm}, Usages={key_usages}",
                            confidence=0.8,
                            snippet=f"ACM Cert: {domain} ({arn})",
                        )],
                        location=Location(uri=f"aws:acm:{region}:{arn}"),
                        implementation=Implementation(library="AWS ACM", provider="aws", api="ACM"),
                        context=Context(exposure=Exposure.INTERNET_FACING, environment=region),
                    ))
        except Exception:
            pass

        return findings

    def _scan_elb(self, region: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            elb = self._session.client("elb", region_name=region)
            paginator = elb.get_paginator("describe_load_balancers")

            for page in paginator.paginate():
                for lb in page.get("LoadBalancerDescriptions", []):
                    name = lb.get("LoadBalancerName", "")
                    for listener in lb.get("ListenerDescriptions", []):
                        listener_info = listener.get("Listener", {})
                        protocol = listener_info.get("Protocol", "")
                        port = listener_info.get("LoadBalancerPort", 0)
                        ssl_cert_id = listener_info.get("SSLCertificateId", "")

                        if protocol in ("HTTPS", "SSL"):
                            findings.append(ScannerFinding(
                                canonical="TLS1.2",
                                original=f"ELB {protocol}",
                                usage_state=UsageState.PROVIDED_ONLY,
                                confidence=0.7,
                                evidence=[create_evidence_signal(
                                    tool="cloud-aws",
                                    detail=f"ELB Listener: {name}, Protocol={protocol}, Port={port}, Cert={ssl_cert_id}",
                                    confidence=0.7,
                                    snippet=f"ELB {name}: {protocol}:{port}",
                                )],
                                location=Location(uri=f"aws:elb:{region}:{name}"),
                                implementation=Implementation(library="AWS ELB", provider="aws", api="ELB"),
                                context=Context(exposure=Exposure.INTERNET_FACING, environment=region),
                            ))
        except Exception:
            pass

        return findings

    def _scan_alb(self, region: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            elbv2 = self._session.client("elbv2", region_name=region)
            paginator = elbv2.get_paginator("describe_load_balancers")

            for page in paginator.paginate():
                for lb in page.get("LoadBalancers", []):
                    lb_arn = lb.get("LoadBalancerArn", "")
                    lb_name = lb.get("LoadBalancerName", "")

                    try:
                        listeners = elbv2.describe_listeners(LoadBalancerArn=lb_arn)
                        for listener in listeners.get("Listeners", []):
                            protocol = listener.get("Protocol", "")
                            port = listener.get("Port", 0)
                            certs = listener.get("Certificates", [])
                            ssl_policy = listener.get("SslPolicy", "")

                            if protocol in ("HTTPS", "TLS"):
                                for cert in certs:
                                    cert_arn = cert.get("CertificateArn", "")
                                    findings.append(ScannerFinding(
                                        canonical="TLS1.2",
                                        original=f"ALB {protocol}",
                                        usage_state=UsageState.PROVIDED_ONLY,
                                        confidence=0.7,
                                        evidence=[create_evidence_signal(
                                            tool="cloud-aws",
                                            detail=f"ALB Listener: {lb_name}, Protocol={protocol}, Port={port}, Cert={cert_arn}, SslPolicy={ssl_policy}",
                                            confidence=0.7,
                                            snippet=f"ALB {lb_name}: {protocol}:{port} (policy: {ssl_policy})",
                                        )],
                                        location=Location(uri=f"aws:alb:{region}:{lb_name}"),
                                        implementation=Implementation(library="AWS ALB", provider="aws", api="ELBv2"),
                                        context=Context(exposure=Exposure.INTERNET_FACING, environment=region),
                                    ))
                    except Exception:
                        continue
        except Exception:
            pass

        return findings

    def _map_kms_key_spec(self, key_spec: str) -> tuple[str, str]:
        mapping = {
            "SYMMETRIC_DEFAULT": ("AES-256-GCM", "AES-256-GCM"),
            "AES_256": ("AES-256-GCM", "AES-256"),
            "AES_128": ("AES-128-GCM", "AES-128"),
            "RSA_2048": ("RSA", "RSA-2048"),
            "RSA_3072": ("RSA", "RSA-3072"),
            "RSA_4096": ("RSA", "RSA-4096"),
            "ECC_NIST_P256": ("ECDSA", "ECDSA-P256"),
            "ECC_NIST_P384": ("ECDSA", "ECDSA-P384"),
            "ECC_NIST_P521": ("ECDSA", "ECDSA-P521"),
            "ECC_SECG_P256K1": ("ECDSA", "ECDSA-secp256k1"),
            "HMAC_256": ("HMAC", "HMAC-SHA256"),
            "HMAC_384": ("HMAC", "HMAC-SHA384"),
            "HMAC_512": ("HMAC", "HMAC-SHA512"),
        }
        return mapping.get(key_spec, ("KMS Key", key_spec))

    def _get_kms_key_size(self, key_spec: str) -> int | None:
        sizes = {
            "SYMMETRIC_DEFAULT": 256,
            "AES_256": 256,
            "AES_128": 128,
            "RSA_2048": 2048,
            "RSA_3072": 3072,
            "RSA_4096": 4096,
            "ECC_NIST_P256": 256,
            "ECC_NIST_P384": 384,
            "ECC_NIST_P521": 521,
            "ECC_SECG_P256K1": 256,
            "HMAC_256": 256,
            "HMAC_384": 384,
            "HMAC_512": 512,
        }
        return sizes.get(key_spec)

    def _get_acm_key_size(self, key_algorithm: str) -> int | None:
        sizes = {
            "RSA_2048": 2048,
            "RSA_4096": 4096,
            "EC_prime256v1": 256,
            "EC_secp384r1": 384,
            "EC_secp521r1": 521,
        }
        return sizes.get(key_algorithm)