"""Builds code.zip with only the submission files (no dataset/, data/, caches, secrets, archives)."""
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {"__pycache__", ".pytest_cache", ".venv", "venv", ".cache"}
SKIP_SUFFIX = {".pyc", ".zip"}


def main() -> None:
    out = ROOT / "code.zip"
    out.unlink(missing_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(ROOT / "README.md", "README.md")
        for p in sorted((ROOT / "code").rglob("*")):
            if p.is_file() and not SKIP_DIRS & set(p.parts) and p.suffix not in SKIP_SUFFIX:
                z.write(p, p.relative_to(ROOT).as_posix())
    print("wrote", out)


if __name__ == "__main__":
    main()
