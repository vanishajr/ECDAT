"""CLI command handlers (thin orchestration over CoreClient + store).

Shared exit codes: 0 success, 1 general error, 2 target not found,
3 validation failure.
"""

SUCCESS = 0
ERROR = 1
TARGET_NOT_FOUND = 2
VALIDATION_FAILED = 3
