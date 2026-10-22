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
    assert ENTITY in (metadata.get("Author-email") or metadata.get("Author", "")), metadata


def check_wheel(path: Path) -> None:
    """Require attribution in the wheel's standard metadata directory."""
    with zipfile.ZipFile(path) as archive:
        metadata = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        assert len(metadata) == 1, path
        prefix = metadata[0].removesuffix("METADATA")
        check_metadata(archive.read(metadata[0]))
        for name in ("LICENSE.txt", "NOTICE.txt"):
            data = archive.read(prefix + "licenses/" + name)
            assert ENTITY.encode() in data, (path, name)
            if name == "NOTICE.txt":
                assert data == NOTICE, path


def check_sdist(path: Path) -> None:
    """Require the same canonical attribution in the source archive."""
    with tarfile.open(path) as archive:
        prefix = path.name.removesuffix(".tar.gz") + "/"
        metadata = archive.extractfile(prefix + "PKG-INFO")
        assert metadata is not None, path
        check_metadata(metadata.read())
        for name in ("LICENSE.txt", "NOTICE.txt"):
            member = archive.extractfile(prefix + name)
            assert member is not None, (path, name)
            data = member.read()
            assert ENTITY.encode() in data, (path, name)
            if name == "NOTICE.txt":
                assert data == NOTICE, path


if __name__ == "__main__":
    directory = Path(sys.argv[1] if len(sys.argv) > 1 else "dist")
    wheels = list(directory.glob("*.whl"))
    sdists = list(directory.glob("*.tar.gz"))
    assert wheels and sdists, f"expected a wheel and sdist in {directory}"
    for wheel in wheels:
        check_wheel(wheel)
    for sdist in sdists:
        check_sdist(sdist)
    print("Distribution attribution passed.")
