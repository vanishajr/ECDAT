# Optional scanner capabilities

ECDAT's production pipeline does not require optional tools to produce a
result. Availability is detected per scan and missing tools are reported in
the plan, diagnostics, coverage view, and reports; absence is never treated as
zero findings.

| Capability | Optional tools | Effect when unavailable |
|---|---|---|
| Source rules/AST | Semgrep, Tree-sitter bindings | Built-in language scanners still run; coverage is disclosed |
| Executable metadata | LIEF | Strings/signature stages may still run |
| Binary signatures | YARA/YARA-X | Other binary stages remain available |
| Binary behavior/strings | capa, FLOSS | Escalation coverage is reduced and recorded |
| Containers/SBOM | Docker/OCI tooling, Syft, cdxgen, Trivy | Local archive/rootfs evidence can still be scanned where supported |
| Runtime TLS/SSH | SSLyze/testssl, endpoint access | Runtime remains opt-in and is reported as unavailable/not requested |
| Cloud inventory | boto3 or provider SDKs and credentials | Cloud remains opt-in; no network call is made without permission |

Install the base project with `pip install -e .`; install only the optional
tools needed for the deployment environment. Use `python -m ecdat.cli --help`
and the scan-plan/coverage output to verify capability state.
