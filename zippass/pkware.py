"""pkware traditional zipcrypto stream cipher - the classic pkzip encryption."""
CRC_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ (0xEDB88320 if _c & 1 else 0)
    CRC_TABLE.append(_c)


class PkDecryptor:
    """decryption side - keys advance on the decrypted (plaintext) bytes, which
    is exactly what the encryption side does, so enc/dec roundtrip cleanly."""

    __slots__ = ("k0", "k1", "k2")

    def __init__(self, pwd: bytes) -> None:
        self.k0, self.k1, self.k2 = 0x12345678, 0x23456789, 0x34567890
        for c in pwd:
            self._up(c)

    def _up(self, c: int) -> None:
        t = self.k0
        self.k0 = (t >> 8) ^ CRC_TABLE[(t ^ c) & 0xFF]
        k1 = self.k1 + (self.k0 & 0xFF)
        self.k1 = (k1 * 134775813 + 1) & 0xFFFFFFFF
        t2 = self.k2
        self.k2 = (t2 >> 8) ^ CRC_TABLE[(t2 ^ (self.k1 >> 24)) & 0xFF]

    def decrypt(self, data: bytes) -> bytes:
        """decrypt an arbitrary-length chunk of the cipher stream."""
        out = bytearray(len(data))
        for i, c in enumerate(data):
            k = self.k2 | 2
            d = c ^ (((k * (k ^ 1)) >> 8) & 0xFF)
            self._up(d)
            out[i] = d
        return bytes(out)
