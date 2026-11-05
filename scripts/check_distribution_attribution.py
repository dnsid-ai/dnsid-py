"""Check attribution in built wheels and source distributions."""

import sys
import tarfile
import zipfile
from email.parser import BytesParser
from pathlib import Path

ENTITY = "Known Systems AI, Inc."
NOTICE = Path(__file__).resolve().parents[1].joinpath("NOTICE.txt").read_bytes()


def check_metadata(data: bytes) -> None:
    """Check the package's legal author, not a dependency's author."""
    metadata = BytesParser().parsebytes(data)
    if ENTITY not in (metadata.get("Author-email") or metadata.get("Author", "")):
        raise ValueError(f"missing author attribution: {metadata}")


def check_wheel(path: Path) -> None:
    """Require attribution in the wheel's standard metadata directory."""
    with zipfile.ZipFile(path) as archive:
        metadata = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        if len(metadata) != 1:
            raise ValueError(f"expected one wheel metadata file: {path}")
        prefix = metadata[0].removesuffix("METADATA")
        check_metadata(archive.read(metadata[0]))
        for name in ("LICENSE.txt", "NOTICE.txt"):
            data = archive.read(prefix + "licenses/" + name)
            if ENTITY.encode() not in data:
                raise ValueError(f"missing attribution in {path}: {name}")
            if name == "NOTICE.txt" and data != NOTICE:
                raise ValueError(f"non-canonical NOTICE.txt: {path}")


def check_sdist(path: Path) -> None:
    """Require the same canonical attribution in the source archive."""
    with tarfile.open(path) as archive:
        prefix = path.name.removesuffix(".tar.gz") + "/"
        metadata = archive.extractfile(prefix + "PKG-INFO")
        if metadata is None:
            raise ValueError(f"missing sdist metadata: {path}")
        check_metadata(metadata.read())
        for name in ("LICENSE.txt", "NOTICE.txt"):
            member = archive.extractfile(prefix + name)
            if member is None:
                raise ValueError(f"missing {name}: {path}")
            data = member.read()
            if ENTITY.encode() not in data:
                raise ValueError(f"missing attribution in {path}: {name}")
            if name == "NOTICE.txt" and data != NOTICE:
                raise ValueError(f"non-canonical NOTICE.txt: {path}")


if __name__ == "__main__":
    directory = Path(sys.argv[1] if len(sys.argv) > 1 else "dist")
    wheels = list(directory.glob("*.whl"))
    sdists = list(directory.glob("*.tar.gz"))
    if not wheels or not sdists:
        raise ValueError(f"expected a wheel and sdist in {directory}")
    for wheel in wheels:
        check_wheel(wheel)
    for sdist in sdists:
        check_sdist(sdist)
    print("Distribution attribution passed.")
