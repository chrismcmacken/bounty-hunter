# Test cases for Python symlink-follow rules
import tarfile
import zipfile

# === TRUE POSITIVES ===

def vulnerable_tar_extract(tar_path, dest):
    tar = tarfile.open(tar_path)
    # ruleid: python-archive-extractall-no-filter
    tar.extractall(dest)

def vulnerable_tar_context(tar_path, dest):
    with tarfile.open(tar_path) as tar:
        # ruleid: python-archive-extractall-no-filter
        tar.extractall(dest)

def vulnerable_zip_extract(zip_path, dest):
    zf = zipfile.ZipFile(zip_path)
    # ruleid: python-archive-extractall-no-filter
    zf.extractall(dest)

def vulnerable_zip_context(zip_path, dest):
    with zipfile.ZipFile(zip_path) as zf:
        # ruleid: python-archive-extractall-no-filter
        zf.extractall(dest)

# === TRUE NEGATIVES ===

def safe_tar_with_filter(tar_path, dest):
    with tarfile.open(tar_path) as tar:
        for member in tar.getmembers():
            if member.issym() or member.islnk():
                continue
            # ok: python-archive-extractall-no-filter
            tar.extract(member, dest)

def safe_zip_with_filter(zip_path, dest):
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.infolist():
            if member.is_symlink():
                continue
            # ok: python-archive-extractall-no-filter
            zf.extract(member, dest)
