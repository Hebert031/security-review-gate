import re
from dataclasses import asdict, dataclass

from .diff_parser import ParsedDiff


TEST_PATH = re.compile(r"(^|/)(tests?|specs?|__tests__)(/|$)|\.(test|spec)\.", re.I)
SENSITIVE_PATH = re.compile(
    r"auth|login|session|permission|rbac|crypto|secret|token|password|middleware|security",
    re.I,
)
INFRA_PATH = re.compile(r"dockerfile|\.github/workflows|k8s|kubernetes|terraform|\.tf$", re.I)
DEPENDENCY_PATH = re.compile(
    r"package(-lock)?\.json|requirements.*\.txt|pyproject\.toml|go\.(mod|sum)|pom\.xml",
    re.I,
)

PATTERNS: dict[str, re.Pattern[str]] = {
    "auth_signals": re.compile(
        r"\bauth(orization|entication)?\b|\bjwt\b|\bsession\b|\brbac\b|\btoken\b",
        re.I,
    ),
    "crypto_signals": re.compile(r"\bencrypt|\bdecrypt|\bcipher|\bhash|\bcrypt|\btls\b", re.I),
    "sql_signals": re.compile(r"\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bexecute\s*\(", re.I),
    "command_signals": re.compile(r"\beval\s*\(|\bexec\s*\(|subprocess|child_process|os\.system", re.I),
    "input_signals": re.compile(r"request\.|req\.|params|query|formdata|upload|deserialize", re.I),
    "secret_signals": re.compile(
        r"api[_-]?key|client[_-]?secret|private[_-]?key|password\s*[=:]|token\s*[=:]",
        re.I,
    ),
    "security_disable_signals": re.compile(
        r"verify\s*=\s*false|rejectUnauthorized\s*:\s*false|disable.*csrf|cors\s*\(\s*\)",
        re.I,
    ),
}


@dataclass(frozen=True)
class DiffFeatures:
    files_changed: int
    lines_added: int
    lines_removed: int
    test_files_changed: int
    sensitive_paths: int
    infrastructure_files: int
    dependency_files: int
    binary_files: int
    auth_signals: int
    crypto_signals: int
    sql_signals: int
    command_signals: int
    input_signals: int
    secret_signals: int
    security_disable_signals: int

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


def extract_features(diff: ParsedDiff) -> DiffFeatures:
    paths = [file.path for file in diff.files]
    added_text = "\n".join(line for file in diff.files for line in file.added_lines)
    pattern_counts = {
        name: len(pattern.findall(added_text)) for name, pattern in PATTERNS.items()
    }

    return DiffFeatures(
        files_changed=len(diff.files),
        lines_added=diff.lines_added,
        lines_removed=diff.lines_removed,
        test_files_changed=sum(bool(TEST_PATH.search(path)) for path in paths),
        sensitive_paths=sum(bool(SENSITIVE_PATH.search(path)) for path in paths),
        infrastructure_files=sum(bool(INFRA_PATH.search(path)) for path in paths),
        dependency_files=sum(bool(DEPENDENCY_PATH.search(path)) for path in paths),
        binary_files=sum(file.binary for file in diff.files),
        **pattern_counts,
    )
