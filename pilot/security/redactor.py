"""Secret redaction engine for Linux Command Pilot.

Redacts passwords, API keys, tokens, private keys, and credential patterns
before any tool output or file content enters the model's context or logs.
"""

import re
from typing import List, Pattern, Tuple

# Compiled regex patterns and their replacement tags
REDACTION_RULES: List[Tuple[Pattern, str]] = [
    # 1. Private keys (PEM / OpenSSH / RSA)
    (
        re.compile(
            r"-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP)?\s*PRIVATE KEY-----[\s\S]*?-----END (?:RSA|OPENSSH|DSA|EC|PGP)?\s*PRIVATE KEY-----",
            re.IGNORECASE,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    # 2. AWS Access Key IDs
    (
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "[REDACTED_AWS_KEY_ID]",
    ),
    # 3. AWS Secret Access Keys
    (
        re.compile(
            r"(?i)(?:aws[_\-\s]?secret[_\-\s]?(?:key|access|token)?['\"\s:=]+)([a-zA-Z0-9/+=]{40})",
        ),
        r"\g<0>"[0:0] + "[REDACTED_AWS_SECRET_KEY]",
    ),
    # 4. GitHub tokens
    (
        re.compile(r"\bgh[pousr]_[0-9a-zA-Z]{36,}\b"),
        "[REDACTED_GITHUB_TOKEN]",
    ),
    # 5. Auth headers (e.g. Authorization: Bearer <token>)
    (
        re.compile(
            r"(?i)(authorization:\s*(?:bearer|basic|token)\s+)(?!(?:\[REDACTED_))([a-zA-Z0-9_\-\.=+/]{8,})",
        ),
        r"\g<1>[REDACTED_AUTH_HEADER]",
    ),
    # 6. Generic API keys / Bearer tokens
    (
        re.compile(
            r"(?i)((?:api[_\-\s]?key|bearer|access[_\-\s]?token|auth[_\-\s]?token)['\"\s:=]+)(?!(?:\[REDACTED_))([a-zA-Z0-9_\-\.]{16,})",
        ),
        r"\g<1>[REDACTED_API_TOKEN]",
    ),
    # 7. Database / Service URI passwords
    (
        re.compile(
            r"(?i)((?:postgres|postgresql|mysql|mongodb|redis):\/\/[^:]+:)(?!(?:\[REDACTED_))([^@\s]+)(@)",
        ),
        r"\g<1>[REDACTED_DB_PASSWORD]\g<3>",
    ),
    # 8. Explicit password fields
    (
        re.compile(
            r"(?i)(['\"]?(?:password|passwd|pwd|secret)['\"]?\s*[:=]\s*['\"])(?!(?:\[REDACTED_))([^'\"\n\r\t]{3,})(['\"])",
        ),
        r"\g<1>[REDACTED_PASSWORD]\g<3>",
    ),
    # 9. Secret-looking environment variables (e.g. export SECRET_KEY=..., API_KEY=...)
    (
        re.compile(
            r"(?i)\b((?:export\s+)?(?:[A-Z0-9_]*(?:SECRET|TOKEN|APIKEY|API_KEY|AUTH|PRIVATE_KEY)[A-Z0-9_]*)\s*=\s*['\"]?)(?!(?:\[REDACTED_))([^'\"\s\n\r]{3,})(['\"]?)",
        ),
        r"\g<1>[REDACTED_SECRET_VAR]\g<3>",
    ),
]


def redact_secrets(text: str) -> str:
    """Scan text and redact sensitive secrets according to configured rules."""
    if not text:
        return text

    sanitized = text
    for pattern, replacement in REDACTION_RULES:
        sanitized = pattern.sub(replacement, sanitized)

    return sanitized
