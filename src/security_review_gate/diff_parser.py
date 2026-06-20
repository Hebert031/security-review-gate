from dataclasses import dataclass, field


MAX_DIFF_BYTES = 2 * 1024 * 1024


@dataclass
class FileChange:
    path: str
    added_lines: list[str] = field(default_factory=list)
    removed_lines: list[str] = field(default_factory=list)
    binary: bool = False


@dataclass
class ParsedDiff:
    files: list[FileChange]

    @property
    def lines_added(self) -> int:
        return sum(len(file.added_lines) for file in self.files)

    @property
    def lines_removed(self) -> int:
        return sum(len(file.removed_lines) for file in self.files)


def _safe_path(raw: str) -> str:
    path = raw.strip().split("\t", 1)[0]
    if path.startswith("b/"):
        path = path[2:]
    if path == "/dev/null":
        return "deleted-file"
    return path[:500]


def parse_unified_diff(content: str) -> ParsedDiff:
    """Interpreta metadados de um diff sem aplicar ou executar seu conteúdo."""
    if len(content.encode("utf-8")) > MAX_DIFF_BYTES:
        raise ValueError("Diff excede o limite de 2 MiB.")

    files: list[FileChange] = []
    current: FileChange | None = None

    for line in content.splitlines():
        if line.startswith("diff --git "):
            parts = line.split(" ", 3)
            path = _safe_path(parts[3]) if len(parts) == 4 else "unknown"
            current = FileChange(path=path)
            files.append(current)
            continue

        if current is None:
            continue

        if line.startswith("+++ "):
            current.path = _safe_path(line[4:])
        elif line.startswith("Binary files ") or line.startswith("GIT binary patch"):
            current.binary = True
        elif line.startswith("+") and not line.startswith("+++"):
            current.added_lines.append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            current.removed_lines.append(line[1:])

    return ParsedDiff(files=files)
