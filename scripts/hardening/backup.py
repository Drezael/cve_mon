"""Authenticated, bounded-memory file envelopes for operator-controlled off-host backups.

The independently provisioned 32-byte base64 key is never placed beside the backup.
Plaintext sources remain operator-owned; they are not silently deleted or rotated.
"""

import base64
import os
import stat
import struct
from pathlib import Path
from uuid import uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cve_common.config.secrets import read_secret

MAGIC = b"CVEBKP02"
LEGACY = b"CVEBKP01"
CHUNK = 65536
MAX_BYTES = 64 * 1024**3


def key_from_file(path: Path) -> bytes:
    try:
        key = base64.b64decode(read_secret(path).get_secret_value(), validate=True)
    except ValueError:
        raise ValueError("Private base64 backup key required") from None
    if len(key) != 32:
        raise ValueError("Backup key must contain 32 random bytes")
    return key


def transform(source: Path, target: Path, key_file: Path, *, decrypt: bool = False) -> None:
    """Authenticate all chunks and the terminator before publishing any decrypted file."""
    key = key_from_file(key_file)
    temporary = target.with_name(target.name + "." + uuid4().hex + ".partial")
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        with os.fdopen(fd, "rb") as incoming:
            info = os.fstat(incoming.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES + 32 * (
                MAX_BYTES // CHUNK
            ):
                raise ValueError("Bounded regular backup file required")
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise ValueError("Backup source must be private")
            if target.exists() or target.is_symlink():
                raise ValueError("Backup destination must be new")
            out_fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(out_fd, "wb") as outgoing:
                if decrypt:
                    magic = incoming.read(8)
                    if magic not in {MAGIC, LEGACY}:
                        raise ValueError("Unsupported backup envelope")
                    tail_size = 32 if magic == MAGIC else 8
                    tail = incoming.read(tail_size)
                    if len(tail) != tail_size:
                        raise ValueError("Truncated backup header")
                    header = magic + tail
                else:
                    header = MAGIC + os.urandom(32)
                    outgoing.write(header)
                legacy = header.startswith(LEGACY)
                file_key = (
                    key
                    if legacy
                    else HKDF(
                        algorithm=hashes.SHA256(), length=32, salt=header[8:], info=MAGIC
                    ).derive(key)
                )
                cipher = AESGCM(file_key)
                count = 0
                size = 0
                while True:
                    counter = struct.pack(">I", count)
                    nonce = (header[8:] if legacy else bytes(8)) + counter
                    if decrypt:
                        length = incoming.read(4)
                        if len(length) != 4:
                            raise ValueError("Missing authenticated backup terminator")
                        length_value = struct.unpack(">I", length)[0]
                        if not 16 <= length_value <= CHUNK + 16:
                            raise ValueError("Invalid backup chunk")
                        data = incoming.read(length_value)
                        final = length_value == 16
                        data = cipher.decrypt(nonce, data, header + counter + bytes([final]))
                    else:
                        data = incoming.read(CHUNK)
                        final = not data
                        data = cipher.encrypt(nonce, data, header + counter + bytes([final]))
                        outgoing.write(struct.pack(">I", len(data)))
                    outgoing.write(data)
                    if final:
                        if decrypt and incoming.read(1):
                            raise ValueError("Trailing backup data")
                        break
                    count += 1
                    size += len(data)
                    if size > MAX_BYTES or count >= 2**32:
                        raise ValueError("Backup size limit")
                outgoing.flush()
                os.fsync(outgoing.fileno())
            # Exclusive publication also rejects races/symlinks at the destination.
            os.link(temporary, target)
    except (InvalidTag, OSError, ValueError, struct.error):
        raise ValueError("Backup unavailable, invalid or authentication failed") from None
    finally:
        temporary.unlink(missing_ok=True)
