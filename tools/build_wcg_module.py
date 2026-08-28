#!/usr/bin/env python3
"""Package the wcg_f946b KernelSU module into a flashable zip.

Layout: module files at the zip root (module.prop first), matching what
`ksud module install` expects. A minimal META-INF is included so the same zip
also installs through managers that expect an updater script.

Usage:
    python tools/build_wcg_module.py [--out dist/wcg_f946b]
"""

import argparse
import re
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULE_DIR = REPO_ROOT / "modules" / "wcg_f946b"

# Files that must be present and their order at the front of the archive.
REQUIRED = ["module.prop"]
SCRIPTS = ["customize.sh", "post-fs-data.sh", "service.sh", "uninstall.sh"]


def read_version(module_prop: Path) -> str:
    text = module_prop.read_text(encoding="utf-8")
    match = re.search(r"^version=(.+)$", text, re.MULTILINE)
    if not match:
        raise SystemExit("module.prop missing version=")
    return match.group(1).strip()


def collect_files() -> list[Path]:
    files = []
    for path in sorted(MODULE_DIR.rglob("*")):
        if path.is_file():
            files.append(path)
    return files


def build(out_dir: Path) -> Path:
    if not MODULE_DIR.is_dir():
        raise SystemExit(f"module dir not found: {MODULE_DIR}")

    prop = MODULE_DIR / "module.prop"
    for name in REQUIRED:
        if not (MODULE_DIR / name).is_file():
            raise SystemExit(f"missing required file: {name}")

    version = read_version(prop)
    out_dir.mkdir(parents=True, exist_ok=True)
    zip_path = out_dir / f"wcg_f946b-{version}.zip"

    files = collect_files()

    # Order: module.prop, scripts, then everything else (system/, README, ...).
    def sort_key(p: Path) -> tuple:
        rel = p.relative_to(MODULE_DIR).as_posix()
        if rel == "module.prop":
            return (0, rel)
        if rel in SCRIPTS:
            return (1, rel)
        return (2, rel)

    files.sort(key=sort_key)

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in files:
            arcname = path.relative_to(MODULE_DIR).as_posix()
            info = zipfile.ZipInfo.from_file(path, arcname)
            # Preserve/set the executable bit on shell scripts so installers
            # that honour the zip mode (and KernelSU's own extraction) can run
            # them. 0o755 in the high 16 bits of external_attr.
            if path.suffix == ".sh":
                info.external_attr = 0o755 << 16
            else:
                info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, path.read_bytes())

    print(f"wrote {zip_path} ({zip_path.stat().st_size} bytes)")
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            print(f"  {info.file_size:>8}  {info.filename}")
    return zip_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "dist" / "wcg_f946b",
        help="output directory for the zip",
    )
    args = parser.parse_args()
    build(args.out)


if __name__ == "__main__":
    main()
