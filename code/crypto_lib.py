"""
================================================================================
  crypto_lib.py  —  Cryptography Library (Python built-ins edition)
================================================================================
  Same public API as the hand-coded version — crypto_gui.py needs zero changes.

  What changed vs the scratch-built version:
    • Base64   → uses Python's built-in base64 module
    • Hex      → uses bytes.hex() and bytes.fromhex()
    • URL      → uses urllib.parse.quote / unquote
    • SHA-256  → uses hashlib.sha256
    • SHA-512  → uses hashlib.sha512
    • Salted Hash → hashlib + os.urandom
    • AES      → uses cryptography library (pip install cryptography)
    • DES      → uses cryptography library
    • 3DES     → uses cryptography library
    • RSA      → uses cryptography library
    • Password Generator → simplified: length + 4 toggles, no exclude/no-repeat

  Install dependency once:
      pip install cryptography

  Everything else (function names, return types, class interfaces) is identical
  to the original, so crypto_gui.py works without any modification.
================================================================================
"""

# Standard library
import os                               # os.urandom() — cryptographic random bytes
import base64 as _b64                   # built-in base64 encode/decode
import hashlib                          # SHA-256, SHA-512
import hmac                             # constant-time compare (for salted verify)
import secrets                          # secrets.choice() — secure random picks
import string                           # string.ascii_* / digits / punctuation
import re                               # regex for pattern detection in strength test
from urllib.parse import (              # URL encoding / decoding
    quote  as _url_quote,
    unquote as _url_unquote,
)

# Third-party (pip install cryptography)
try:
    from cryptography.hazmat.primitives.ciphers import (
        Cipher, algorithms, modes,      # AES cipher objects and modes
    )
    # TripleDES moved to 'decrepit' package in cryptography >= 44
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import (
            TripleDES as _TripleDES,    # new location (cryptography >= 44)
        )
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.algorithms import (
            TripleDES as _TripleDES,    # old location (cryptography < 44)
        )
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa_gen
    from cryptography.hazmat.primitives.asymmetric import padding as _rsa_padding
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _CRYPTO_OK = True                   # flag: cryptography library is available
except ImportError:
    _CRYPTO_OK = False                  # flag: library missing — show clear error


def _require_crypto():
    """Raise a clear error if the cryptography library is not installed."""
    if not _CRYPTO_OK:
        raise RuntimeError(
            "The 'cryptography' library is required.\n"
            "Install it with:  pip install cryptography"
        )


# ------------------------------------------------SECTION 0 — SHARED HELPERS---------------------------------------------------
# change bytes to int numbers
def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")     # built-in replaces the manual loop

# change int to bytes
def _int_to_bytes(n: int, length: int) -> bytes:
    """Convert an integer to big-endian bytes of exactly `length` bytes."""
    return n.to_bytes(length, "big")    # built-in replaces the manual loop

#xor operation
def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two equal-length byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))  # kept as-is — already simple

# in the whoule code we using zero bading
def _zero_pad(data: bytes, block_size: int) -> bytes:
    """Right-pad data with zero bytes to the next multiple of block_size."""
    remainder = len(data) % block_size
    if remainder == 0:
        return data                     # already aligned — nothing to do
    return data + b'\x00' * (block_size - remainder)  # append zero bytes

# also help in unpading and decoding sections
def _unpad_zeros(data: bytes) -> bytes:
    """Strip trailing zero bytes that were added by _zero_pad."""
    return data.rstrip(b'\x00')         # built-in bytes method

# Add 1 to a big-endian counter block, wrapping on overflow.
def _increment_counter(counter: bytes) -> bytes:
    n = _bytes_to_int(counter) + 1      # convert, increment
    return _int_to_bytes(n % (1 << (len(counter) * 8)), len(counter))  # wrap


#  SECTION 1 — BASE64
#  Thin wrappers around Python's built-in base64 module.

# encoding using base64 libarary, 
def base64_encode(data: bytes) -> str:

    return _b64.b64encode(data).decode("ascii")  # encode then strip the b'' wrapper

# decoding also using base64 libarary.
def base64_decode(s: str) -> bytes:
   
    return _b64.b64decode(s)            # built-in handles padding and decoding


#------------------------------------SECTION 2 — HEX ENCODING------------------------------------------------------------------

# Uses bytes.hex() and bytes.fromhex().
def hex_encode(data: bytes) -> str:
    """
    Encode raw bytes to a lowercase hex string.

    Uses the built-in bytes.hex() method which produces two hex chars per byte.

    Parameters
    ----------
    data : bytes

    Returns
    -------
    str  — lowercase hex string (2 characters per input byte)
    """
    return data.hex()                   # e.g. b'\xde\xad' → 'dead'

#decoding using bytes libarary also
def hex_decode(s: str) -> bytes:
    """
    Decode a hex string back to raw bytes.

    Uses the built-in bytes.fromhex() which validates and converts the string.

    Parameters
    ----------
    s : str  — hex-encoded string (must have even length)

    Returns
    -------
    bytes
    """
    return bytes.fromhex(s)             # e.g. 'dead' → b'\xde\xad'


# ------------------------------------SECTION 3 — URL ENCODING  (RFC 3986)------------------------------------------------

#  Uses urllib.parse.quote / unquote.
def url_encode(text: str) -> str:
    """
    Percent-encode a string per RFC 3986.

    Uses urllib.parse.quote() with safe='' so every non-unreserved character
    is encoded, including spaces (→ %20) and Arabic / Unicode characters.

    Parameters
    ----------
    text : str

    Returns
    -------
    str  — percent-encoded string
    """
    return _url_quote(text, safe="")    # safe='' means nothing is left unencoded

#decoding section for url
def url_decode(text: str) -> str:
    """
    Decode a percent-encoded string back to plain Unicode text.

    Uses urllib.parse.unquote() which handles %XX sequences and UTF-8 decoding.
    Supports Arabic, emoji, and all Unicode characters.

    Parameters
    ----------
    text : str  — percent-encoded string

    Returns
    -------
    str  — decoded plain text
    """
    return _url_unquote(text)           # handles %XX → character, UTF-8 aware


#----------------------------------------SECTION 4 — SHA-256--------------------------------------------------------

#  Uses hashlib.sha256 — part of Python's standard library.
def sha256(data: bytes) -> bytes:
    """
    Compute the SHA-256 digest of data.

    Uses Python's built-in hashlib.sha256 (backed by OpenSSL internally).

    Parameters
    ----------
    data : bytes

    Returns
    -------
    bytes  — 32-byte (256-bit) digest
    """
    return hashlib.sha256(data).digest()    # .digest() returns raw bytes


def sha256_hex(data: bytes) -> str:
    """Return SHA-256 digest as a lowercase hex string."""
    return hashlib.sha256(data).hexdigest() # .hexdigest() returns lowercase hex



#-----------------------------------------SECTION 5 — SHA-512----------------------------------------------------------------

#  Uses hashlib.sha512.
def sha512(data: bytes) -> bytes:
    """
    Compute the SHA-512 digest of data.

    Uses Python's built-in hashlib.sha512.

    Parameters
    ----------
    data : bytes

    Returns
    -------
    bytes  — 64-byte (512-bit) digest
    """
    return hashlib.sha512(data).digest()    # .digest() returns raw bytes

# this part to make it able to read
def sha512_hex(data: bytes) -> str:
    """Return SHA-512 digest as a lowercase hex string."""
    return hashlib.sha512(data).hexdigest() # .hexdigest() returns lowercase hex


#---------------------------------------SECTION 6 — SALTED HASHING--------------------------------------------------------

#  SHA-256 with a random 16-byte salt prepended before hashing.
_SALT_BYTES = 16    # 128-bit random salt — same size as original

# the salted hashing
def salted_hash(password: str, salt: bytes = None) -> dict:
    """
    Hash a password with a random salt using SHA-256.

    Construction:  digest = SHA-256( salt || password_utf8 )

    Parameters
    ----------
    password : str   — plain-text password
    salt     : bytes — optional; generated randomly if not provided

    Returns
    -------
    dict with:
        'salt' : hex-encoded salt string
        'hash' : hex-encoded SHA-256 digest string
    """
    if salt is None:
        salt = os.urandom(_SALT_BYTES)          # 16 cryptographically random bytes
    combined = salt + password.encode("utf-8")  # prepend salt to password bytes
    digest   = hashlib.sha256(combined).digest() # SHA-256 of salt+password
    return {
        "salt": hex_encode(salt),               # return hex strings for easy storage
        "hash": hex_encode(digest),
    }

# check the salted hash
def salted_hash_verify(password: str, stored_salt_hex: str, stored_hash_hex: str) -> bool:
    """
    Verify a password against a stored salt + hash pair.

    Uses hmac.compare_digest() for constant-time comparison to prevent
    timing attacks that could reveal partial hash information.

    Parameters
    ----------
    password        : str — plain-text password to verify
    stored_salt_hex : str — hex salt from salted_hash()
    stored_hash_hex : str — hex hash from salted_hash()

    Returns
    -------
    bool — True if the password matches
    """
    salt      = hex_decode(stored_salt_hex)         # recover the original salt bytes
    result    = salted_hash(password, salt=salt)    # re-derive hash with same salt
    return hmac.compare_digest(                     # constant-time comparison
        result["hash"], stored_hash_hex
    )


#-----------------------------SECTION 7 — AES  (uses cryptography library)-----------------------------------------------------

#  Modes supported: ECB, CBC, CFB, OFB, CTR, GCM
#  Key sizes      : 16 bytes (AES-128), 24 bytes (AES-192), 32 bytes (AES-256)
#  Padding        : Zero-padding for block modes; stream modes need no padding
#  Output         : Base64 string for all encrypt() calls

#the AES class
class AES:
    """
    AES encryption / decryption — same API as the original hand-coded version.

    Usage (unchanged from original):
        aes = AES(key)
        ct  = aes.encrypt(plaintext, mode='CBC', iv=my_iv)
        pt  = aes.decrypt(ct,        mode='CBC', iv=my_iv)

    GCM mode returns a dict: {'ciphertext': b64, 'tag': b64, 'iv': b64}
    All other modes return a Base64 string.
    """

    BLOCK = 16  # AES block size is always 128 bits = 16 bytes

    #Store the key; validation happens inside each cipher instantiation
    def __init__(self, key: bytes):
        _require_crypto()               # fail fast if library not installed
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24, or 32 bytes.")
        self._key = key                 # store key for later use

    # the main code
    def encrypt(self, plaintext: bytes, mode: str = 'CBC',
                iv: bytes = None, aad: bytes = b"") -> str:
        """
        Encrypt plaintext and return a Base64-encoded string.

        Parameters
        ----------
        plaintext : bytes
        mode      : 'ECB' | 'CBC' | 'CFB' | 'OFB' | 'CTR' | 'GCM'
        iv        : bytes — auto-generated if None (16 bytes for most modes,
                            12 bytes for GCM)
        aad       : bytes — additional authenticated data (GCM only)

        Returns
        -------
        str (Base64) for all modes except GCM.
        dict {'ciphertext', 'tag', 'iv'} for GCM.
        """
        mode = mode.upper()

        # GCM: handled by AESGCM which manages IV and tag automatically
        if mode == 'GCM':
            if iv is None:
                iv = os.urandom(12)                 # GCM standard nonce = 12 bytes
            aesgcm = AESGCM(self._key)              # instantiate AESGCM cipher
            # encrypt_and_digest: ciphertext has the 16-byte tag appended
            ct_with_tag = aesgcm.encrypt(iv, plaintext, aad or None)
            ct  = ct_with_tag[:-16]                 # everything except last 16 bytes
            tag = ct_with_tag[-16:]                 # last 16 bytes are the auth tag
            return {
                "ciphertext": base64_encode(ct),
                "tag":        base64_encode(tag),
                "iv":         base64_encode(iv),
            }

        #ECB note: no IV needed***
        if mode == 'ECB':
            data    = _zero_pad(plaintext, self.BLOCK)  # pad to block boundary
            cipher  = Cipher(algorithms.AES(self._key), modes.ECB(),
                             backend=default_backend())
            enc     = cipher.encryptor()
            ct      = enc.update(data) + enc.finalize()
            return base64_encode(ct)

        #All other modes need an IV
        if iv is None:
            iv = os.urandom(self.BLOCK)             # generate random 16-byte IV

        # code by mode CBC
        if mode == 'CBC':
            data   = _zero_pad(plaintext, self.BLOCK)
            cipher = Cipher(algorithms.AES(self._key), modes.CBC(iv),
                            backend=default_backend())
            enc    = cipher.encryptor()
            ct     = enc.update(data) + enc.finalize()

        # code by mode CFB
        elif mode == 'CFB':
            # CFB8 by default in cryptography library; use CFB (128-bit feedback)
            cipher = Cipher(algorithms.AES(self._key), modes.CFB(iv),
                            backend=default_backend())
            enc    = cipher.encryptor()
            ct     = enc.update(plaintext) + enc.finalize()

        # code by mode OFB
        elif mode == 'OFB':
            cipher = Cipher(algorithms.AES(self._key), modes.OFB(iv),
                            backend=default_backend())
            enc    = cipher.encryptor()
            ct     = enc.update(plaintext) + enc.finalize()

        # code by mode CTR
        elif mode == 'CTR':
            # CTR mode uses a nonce (called iv here for API consistency)
            cipher = Cipher(algorithms.AES(self._key),
                            modes.CTR(iv),          # iv acts as the initial counter
                            backend=default_backend())
            enc    = cipher.encryptor()
            ct     = enc.update(plaintext) + enc.finalize()

        else:
            raise ValueError(f"Unknown AES mode: {mode}")

        return base64_encode(ct)

    # the main decoding section
    def decrypt(self, ciphertext_b64: str, mode: str = 'CBC',
                iv: bytes = None, tag: bytes = None, aad: bytes = b"") -> bytes:
        """
        Decrypt a Base64-encoded ciphertext and return plaintext bytes.

        Parameters
        ----------
        ciphertext_b64 : str   — Base64 ciphertext (or raw bytes for GCM)
        mode           : str
        iv             : bytes — must match the IV used during encrypt
        tag            : bytes — GCM authentication tag
        aad            : bytes — additional authenticated data (GCM only)

        Returns
        -------
        bytes — plaintext
        """
        mode = mode.upper()
        ct   = base64_decode(ciphertext_b64) if isinstance(ciphertext_b64, str) \
               else ciphertext_b64             # accept both str and bytes
        
        # decoding by mode GCM
        if mode == 'GCM':
            if iv is None or tag is None:
                raise ValueError("GCM decrypt requires both iv and tag.")
            aesgcm   = AESGCM(self._key)
            combined = ct + tag                 # AESGCM.decrypt expects ct+tag
            return aesgcm.decrypt(iv, combined, aad or None)
        
        # decoding by mode ECB
        if mode == 'ECB':
            cipher = Cipher(algorithms.AES(self._key), modes.ECB(),
                            backend=default_backend())
            dec    = cipher.decryptor()
            pt     = dec.update(ct) + dec.finalize()
            return _unpad_zeros(pt)             # strip zero padding

        if iv is None:
            raise ValueError(f"AES {mode} decrypt requires an IV.")
        
        # decoding by mode CBC
        if mode == 'CBC':
            cipher = Cipher(algorithms.AES(self._key), modes.CBC(iv),
                            backend=default_backend())
            dec    = cipher.decryptor()
            pt     = dec.update(ct) + dec.finalize()
            return _unpad_zeros(pt)

        # decoding by mode CFB
        elif mode == 'CFB':
            cipher = Cipher(algorithms.AES(self._key), modes.CFB(iv),
                            backend=default_backend())
            dec    = cipher.decryptor()
            return dec.update(ct) + dec.finalize()
        
        # decoding by mode OFB
        elif mode == 'OFB':
            cipher = Cipher(algorithms.AES(self._key), modes.OFB(iv),
                            backend=default_backend())
            dec    = cipher.decryptor()
            return dec.update(ct) + dec.finalize()

        # decoding by mode CTR
        elif mode == 'CTR':
            cipher = Cipher(algorithms.AES(self._key), modes.CTR(iv),
                            backend=default_backend())
            dec    = cipher.decryptor()
            return dec.update(ct) + dec.finalize()

        else:
            raise ValueError(f"Unknown AES mode: {mode}")

#-------------------------------SECTION 8 — DES  (uses cryptography library)------------------------------------------
#
#  Key size : 8 bytes (64-bit key, 56 effective bits)
#  Block    : 8 bytes
#  Modes    : ECB, CBC, CFB, OFB, CTR
#  Note     : DES is deprecated — provided for educational purposes only.

# DES code class
class DES:
    """
    DES encryption / decryption — same API as the original.

    Usage:
        des = DES(key)          # key must be exactly 8 bytes
        ct  = des.encrypt(plaintext, mode='CBC', iv=iv)
        pt  = des.decrypt(ct,        mode='CBC', iv=iv)
    """

    BLOCK = 8   # DES block size = 64 bits = 8 bytes
# Internal helper: 
    # section error handling
    def __init__(self, key: bytes):
        _require_crypto()
        if len(key) != 8:
            raise ValueError("DES key must be exactly 8 bytes.")
        self._key = key

    # build a cryptography Cipher object for DES. Returns (cipher_object, needs_padding).        
    def _make_cipher(self, mode_str: str, iv: bytes = None):
       
        mode_str = mode_str.upper()
        if mode_str == 'ECB':
            m = modes.ECB()
        elif mode_str == 'CBC':
            m = modes.CBC(iv)
        elif mode_str == 'CFB':
            m = modes.CFB(iv)           # 8-bit CFB by default for DES
        elif mode_str == 'OFB':
            m = modes.OFB(iv)
        elif mode_str == 'CTR':
            # CTR is not natively in the library for DES — emulate via OFB
            # (both produce a keystream XOR'd with plaintext)
            m = modes.OFB(iv)
        else:
            raise ValueError(f"Unknown DES mode: {mode_str}")
        return Cipher(_TripleDES(self._key * 3),  # DES = 3DES with repeated key (EEE mode)
                      m, backend=default_backend())

    # encryption main section
    def encrypt(self, plaintext: bytes, mode: str = 'CBC', iv: bytes = None) -> str: #the defalut is cbc
        """Encrypt and return Base64 string."""
        mode = mode.upper()
        if mode != 'ECB' and iv is None:
            iv = os.urandom(self.BLOCK)         # auto-generate 8-byte IV
        cipher = self._make_cipher(mode, iv)
        enc    = cipher.encryptor()
        if mode in ('ECB', 'CBC'):
            data = _zero_pad(plaintext, self.BLOCK) # block modes need padding
        else:
            data = plaintext                    # stream modes: no padding needed
        ct = enc.update(data) + enc.finalize()
        return base64_encode(ct)
    
    # decryption main section
    def decrypt(self, ciphertext_b64: str, mode: str = 'CBC', iv: bytes = None) -> bytes:
        """Decrypt a Base64 string and return plaintext bytes."""
        mode = mode.upper()
        ct   = base64_decode(ciphertext_b64) if isinstance(ciphertext_b64, str) \
               else ciphertext_b64
        cipher = self._make_cipher(mode, iv)
        dec    = cipher.decryptor()
        pt     = dec.update(ct) + dec.finalize()
        if mode in ('ECB', 'CBC'):
            return _unpad_zeros(pt)             # strip zero padding for block modes
        return pt


#------------------------------SECTION 9 — TRIPLE-DES  (uses cryptography library)--------------------------------------------
#
#  Key sizes : 16 bytes (2-key EDE) or 24 bytes (3-key EDE)
#  Block     : 8 bytes
#  Modes     : ECB, CBC, CFB, OFB, CTR

# 3DES main class
class TripleDES:
    """
    3DES (Triple-DES) encryption / decryption — same API as the original.

    Usage:
        tdes = TripleDES(key)   # key = 16 or 24 bytes
        ct   = tdes.encrypt(plaintext, mode='CBC', iv=iv)
        pt   = tdes.decrypt(ct,        mode='CBC', iv=iv)
    """

    BLOCK = 8   # 3DES block size = 64 bits = 8 bytes
    # Internal helper: 
    def __init__(self, key: bytes):
        _require_crypto()
        if len(key) not in (16, 24):
            raise ValueError("3DES key must be 16 or 24 bytes.")
        self._key = key
    def _make_cipher(self, mode_str: str, iv: bytes = None):
        """Build a cryptography Cipher object for 3DES."""
        mode_str = mode_str.upper()
        if mode_str == 'ECB':
            m = modes.ECB()
        elif mode_str == 'CBC':
            m = modes.CBC(iv)
        elif mode_str == 'CFB':
            m = modes.CFB(iv)
        elif mode_str == 'OFB':
            m = modes.OFB(iv)
        elif mode_str == 'CTR':
            m = modes.OFB(iv)           # emulate CTR via OFB for 3DES
        else:
            raise ValueError(f"Unknown 3DES mode: {mode_str}")
        return Cipher(_TripleDES(self._key),      # 3DES cipher with the full key
                      m, backend=default_backend())
    # encryption main section for the 3des
    def encrypt(self, plaintext: bytes, mode: str = 'CBC', iv: bytes = None) -> str:
        """Encrypt and return Base64 string."""
        mode = mode.upper()
        if mode != 'ECB' and iv is None:
            iv = os.urandom(self.BLOCK)         # auto-generate 8-byte IV
        cipher = self._make_cipher(mode, iv)
        enc    = cipher.encryptor()
        if mode in ('ECB', 'CBC'):
            data = _zero_pad(plaintext, self.BLOCK)
        else:
            data = plaintext
        ct = enc.update(data) + enc.finalize()
        return base64_encode(ct)
    # decryption main section for the 3des
    def decrypt(self, ciphertext_b64: str, mode: str = 'CBC', iv: bytes = None) -> bytes:
        """Decrypt a Base64 string and return plaintext bytes."""
        mode = mode.upper()
        ct   = base64_decode(ciphertext_b64) if isinstance(ciphertext_b64, str) \
               else ciphertext_b64
        cipher = self._make_cipher(mode, iv)
        dec    = cipher.decryptor()
        pt     = dec.update(ct) + dec.finalize()
        if mode in ('ECB', 'CBC'):
            return _unpad_zeros(pt)
        return pt


#----------------------------------SECTION 10 — RSA  (uses cryptography library)----------------------------------------------
#  Key sizes  : 1024 or 2048 bits
#  Padding    : OAEP (encrypt/decrypt) — stronger than PKCS#1 v1.5
#  Operations : generate, encrypt, decrypt
#  Key format : hex-encoded for GUI display / paste (same as original)

# RSA class code
class RSA:
    """
    RSA public-key cryptography — same public API as the original.

    Usage:
        rsa = RSA.generate(bits=2048)
        ct  = rsa.encrypt(b"Hello")
        pt  = rsa.decrypt(ct)
        pub_hex  = rsa_pub_hex(rsa)     # export for display / storage
        priv_hex = rsa_priv_hex(rsa)    # export for display / storage

    Internal representation uses cryptography library key objects.
    The ._key (private) and ._pub (public) attributes hold those objects.
    The .n, .e, .d properties expose the raw integers for the GUI helpers.
    The ._k property gives the modulus byte length (needed by GUI helpers).
    """
    # Internal helper: 
    def __init__(self, n: int, e: int, d: int = None):
        """
        Reconstruct an RSA instance from raw integer components.
        Used by rsa_from_hex() to rebuild from pasted hex fields.
        """
        _require_crypto()
        self.n = n                              # modulus
        self.e = e                              # public exponent
        self.d = d                              # private exponent (None = public only)
        self._k = (n.bit_length() + 7) // 8    # modulus byte length

        # Build cryptography library key objects from the raw integers
        from cryptography.hazmat.primitives.asymmetric.rsa import (
            RSAPublicNumbers, RSAPrivateNumbers, rsa_crt_iqmp, rsa_crt_dmp1, rsa_crt_dmq1
        )
        pub_numbers = RSAPublicNumbers(e, n)    # public key = (e, n)
        self._pub   = pub_numbers.public_key(default_backend())

        if d is not None:
            # To build a private key we need CRT parameters; derive them from n, e, d
            # Factor n = p * q using a standard algorithm based on e and d
            p, q = self._factor_n(n, e, d)
            priv_numbers = RSAPrivateNumbers(
                p=p, q=q, d=d,
                dmp1 = rsa_crt_dmp1(d, p),     # d mod (p-1)
                dmq1 = rsa_crt_dmq1(d, q),     # d mod (q-1)
                iqmp = rsa_crt_iqmp(p, q),      # q^-1 mod p
                public_numbers=pub_numbers,
            )
            self._key = priv_numbers.private_key(default_backend())
        else:
            self._key = None                    # no private key — encrypt-only

    @staticmethod
    def _factor_n(n: int, e: int, d: int):
        """
        Recover the prime factors p and q from n, e, d.

        Algorithm (standard probabilistic method):
          1. Write e*d - 1 = 2^s * t  (factor out powers of 2)
          2. Pick random a; compute a^t mod n
          3. Square repeatedly looking for a non-trivial square root of 1 mod n
          4. gcd(root - 1, n) gives one of the factors
        """
        import random
        k = e * d - 1                           # k = e*d - 1 = multiple of phi(n)
        # Write k = 2^s * t
        t = k
        while t % 2 == 0:
            t //= 2
        for _ in range(100):                    # try up to 100 random witnesses
            a  = random.randint(2, n - 2)
            x  = pow(a, t, n)                   # a^t mod n
            if x in (1, n - 1):
                continue
            y = x
            while True:
                y = pow(y, 2, n)                # square: a^(2^i * t) mod n
                if y == 1:
                    # Found a non-trivial square root — gcd gives a factor
                    import math
                    p = math.gcd(x - 1, n)
                    if 1 < p < n:
                        return p, n // p        # return (p, q)
                    break
                if y == n - 1:
                    break
                x = y
        raise RuntimeError("Could not factor n from (n, e, d). Key may be corrupt.")

    @classmethod
    def generate(cls, bits: int = 2048) -> 'RSA':
        """
        Generate a new RSA key pair.

        Parameters
        ----------
        bits : int — 1024 or 2048 (4096 also accepted but very slow)

        Returns
        -------
        RSA instance with both public and private key.
        """
        _require_crypto()
        if bits not in (1024, 2048, 4096):
            raise ValueError("RSA bits must be 1024, 2048, or 4096.")
        # Generate key using the cryptography library
        priv = _rsa_gen.generate_private_key(
            public_exponent=65537,              # standard Fermat prime
            key_size=bits,
            backend=default_backend(),
        )
        pub  = priv.public_key()
        # Extract raw integer components for storage and display
        priv_nums = priv.private_numbers()
        n = priv_nums.public_numbers.n          # modulus
        e = priv_nums.public_numbers.e          # public exponent (65537)
        d = priv_nums.d                         # private exponent
        instance = cls.__new__(cls)             # bypass __init__ to avoid re-factoring
        instance.n    = n
        instance.e    = e
        instance.d    = d
        instance._k   = (n.bit_length() + 7) // 8
        instance._key = priv                    # store library key objects directly
        instance._pub = pub
        return instance
    
    # encryption main section
    def encrypt(self, plaintext: bytes) -> str:
        """
        Encrypt plaintext with the RSA public key (OAEP padding).

        Parameters
        ----------
        plaintext : bytes — raw message

        Returns
        -------
        str — Base64-encoded ciphertext
        """
        ct = self._pub.encrypt(
            plaintext,
            _rsa_padding.OAEP(                  # OAEP is stronger than PKCS#1 v1.5
                mgf=_rsa_padding.MGF1(algorithm=_hashes.SHA256()),
                algorithm=_hashes.SHA256(),
                label=None,
            )
        )
        return base64_encode(ct)
    
    # decryption main section
    def decrypt(self, ciphertext_b64: str) -> bytes:
        """
        Decrypt a Base64-encoded ciphertext with the RSA private key.

        Parameters
        ----------
        ciphertext_b64 : str — Base64-encoded ciphertext

        Returns
        -------
        bytes — original plaintext
        """
        if self._key is None:
            raise RuntimeError("Private key not available — cannot decrypt.")
        ct = base64_decode(ciphertext_b64)
        return self._key.decrypt(
            ct,
            _rsa_padding.OAEP(
                mgf=_rsa_padding.MGF1(algorithm=_hashes.SHA256()),
                algorithm=_hashes.SHA256(),
                label=None,
            )
        )
    
# RSA hex helpers (used by crypto_gui.py)
def rsa_pub_hex(rsa_obj) -> str:
    """
    Export the RSA public key as a single hex string: n concatenated with e.
    Used by the GUI to display the public key in a copyable field.
    """
    k     = rsa_obj._k                              # modulus byte length
    n_hex = _int_to_bytes(rsa_obj.n, k).hex()       # modulus as hex
    e_hex = _int_to_bytes(rsa_obj.e, 3).hex()       # e=65537 fits in 3 bytes
    return n_hex + e_hex                            # single concatenated string


def rsa_priv_hex(rsa_obj) -> str:
    """
    Export the RSA private key as a single hex string: n concatenated with d.
    Used by the GUI to display the private key in a copyable field.
    """
    if not rsa_obj.d:
        return ""                                   # no private key available
    k     = rsa_obj._k
    n_hex = _int_to_bytes(rsa_obj.n, k).hex()
    d_hex = _int_to_bytes(rsa_obj.d, k).hex()
    return n_hex + d_hex


def rsa_from_hex(pub_hex: str, priv_hex: str = "") -> 'RSA':
    """
    Reconstruct an RSA object from hex strings produced by rsa_pub_hex / rsa_priv_hex.

    pub_hex  — concatenation of n_hex + e_hex (public key)
    priv_hex — concatenation of n_hex + d_hex (private key, optional)
    """
    pub_hex  = pub_hex.strip()
    priv_hex = priv_hex.strip()
    if not pub_hex:
        raise ValueError("Public key field is empty.")
    pub_bytes = bytes.fromhex(pub_hex)              # decode hex to bytes
    n_bytes   = pub_bytes[:-3]                      # n = all but last 3 bytes
    e_bytes   = pub_bytes[-3:]                      # e = last 3 bytes (65537)
    n = int.from_bytes(n_bytes, "big")
    e = int.from_bytes(e_bytes, "big")
    d = None
    if priv_hex:
        priv_bytes = bytes.fromhex(priv_hex)
        d_bytes    = priv_bytes[len(n_bytes):]      # d = bytes after n
        d = int.from_bytes(d_bytes, "big")
    return RSA(n, e, d)                             # reconstruct the RSA instance


#-------------------------------SECTION 11 — PASSWORD GENERATOR  (simplified)--------------------------------------------------
#
#  Controls: length slider + 4 character-type toggles (Upper/Lower/Digits/Special)
#  Uses secrets.choice() for cryptographically secure random selection.
#  Strength scoring runs a loop of checks including common-pattern detection
#  and optional rockyou.txt lookup (silently skipped if file not found).

# Character pools — plain strings used as selection sources
_PG_LOWER   = string.ascii_lowercase    # a-z  (26 chars)
_PG_UPPER   = string.ascii_uppercase    # A-Z  (26 chars)
_PG_DIGITS  = string.digits             # 0-9  (10 chars)
_PG_SPECIAL = "!@#$%^&*()-_=+[]{}|;:,.<>?"  # common special characters (27 chars)

# Common keyboard walk patterns that weaken a password
_KEYBOARD_WALKS = [
    "qwerty", "qwert", "werty",         # horizontal rows
    "asdfg", "asdf", "sdfg",
    "zxcvb", "zxcv",
    "12345", "23456", "34567",          # digit sequences
    "98765", "87654",
    "abcde", "bcdef",                   # alphabet sequences
    "aaaaa", "bbbbb",                   # repeated characters
    "11111", "22222", "00000",
    "password", "passwd", "pass",       # obvious words
    "admin", "login", "user",
    "letmein", "welcome", "hello",
]

# rockyou.txt loaded once at module level; empty set if file not found
_ROCKYOU_SET: set = set()               # populated by _load_rockyou() below


def _load_rockyou(path: str = "rockyou.txt") -> set:
    """
    Load rockyou.txt into a set for O(1) membership testing.
    Returns an empty set silently if the file is not found or cannot be read.
    Each entry is lowercased for case-insensitive matching.
    """
    db = set()
    if not os.path.exists(path):
        return db                               # file not found — skip silently
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                db.add(line.strip().lower())    # lowercase all entries
    except Exception:
        pass                                    # any read error — skip silently
    return db


# Load rockyou once when the module is imported
_ROCKYOU_SET = _load_rockyou()


class PasswordGenerator:
    """
    Simple, secure password generator with 4 character-type toggles.

    Usage:
        pg = PasswordGenerator()
        pg.use_uppercase = True
        pg.use_lowercase = True
        pg.use_digits    = True
        pg.use_special   = False
        password = pg.generate(length=16)
        score    = pg.strength("MyP@ss!")

    Properties
    ----------
    use_uppercase : bool   Include A-Z  (default True)
    use_lowercase : bool   Include a-z  (default True)
    use_digits    : bool   Include 0-9  (default True)
    use_special   : bool   Include !@#… (default True)
    min_uppercase : int    Minimum uppercase chars (default 1, set to 0 to disable)
    min_lowercase : int    Minimum lowercase chars (default 1)
    min_digits    : int    Minimum digit chars     (default 1)
    min_special   : int    Minimum special chars   (default 1)
    """

    def __init__(self):
        # Character category toggles
        self.use_uppercase = True
        self.use_lowercase = True
        self.use_digits    = True
        self.use_special   = True
        # Minimum-count requirements per category (set automatically by GUI)
        self.min_uppercase = 1
        self.min_lowercase = 1
        self.min_digits    = 1
        self.min_special   = 1

    def _pool(self) -> str:
        """Build the full character pool from enabled categories."""
        pool = ""
        if self.use_lowercase: pool += _PG_LOWER   # add lowercase letters
        if self.use_uppercase: pool += _PG_UPPER   # add uppercase letters
        if self.use_digits:    pool += _PG_DIGITS  # add digits
        if self.use_special:   pool += _PG_SPECIAL # add special characters
        if not pool:
            raise ValueError("At least one character type must be enabled.")
        return pool

    def generate(self, length: int = 16) -> str:
        """
        Generate a secure random password.

        Strategy:
          1. First satisfy each enabled minimum requirement (guarantees policy).
          2. Fill remaining positions from the full combined pool.
          3. Shuffle the result so required characters aren't always at the start.

        Uses secrets.choice() which is cryptographically secure (backed by
        os.urandom internally).

        Parameters
        ----------
        length : int — desired length (defaults to 16)

        Returns
        -------
        str — the generated password
        """
        if length < 1:
            raise ValueError("Length must be at least 1.")

        chars = []  # accumulate required characters first

        # Step 1: satisfy minimums — guarantees policy even if length is small
        if self.use_lowercase and self.min_lowercase > 0:
            for _ in range(self.min_lowercase):
                chars.append(secrets.choice(_PG_LOWER))   # pick from lowercase pool
        if self.use_uppercase and self.min_uppercase > 0:
            for _ in range(self.min_uppercase):
                chars.append(secrets.choice(_PG_UPPER))   # pick from uppercase pool
        if self.use_digits and self.min_digits > 0:
            for _ in range(self.min_digits):
                chars.append(secrets.choice(_PG_DIGITS))  # pick from digits pool
        if self.use_special and self.min_special > 0:
            for _ in range(self.min_special):
                chars.append(secrets.choice(_PG_SPECIAL)) # pick from special pool

        # Auto-extend length if minimums already exceed requested length
        effective_length = max(length, len(chars))

        # Step 2: fill remaining positions from the full combined pool
        pool = self._pool()
        while len(chars) < effective_length:
            chars.append(secrets.choice(pool))  # each pick is independent and secure

        # Step 3: shuffle so required chars aren't always at fixed positions
        # secrets.SystemRandom provides a cryptographically secure shuffle source
        rng = secrets.SystemRandom()
        rng.shuffle(chars)                      # Fisher-Yates in-place shuffle

        return "".join(chars)

    def non_duplicate(self, length: int = 16) -> str:
        """
        Generate a password where every character appears at most once.

        Builds the pool, removes duplicates, shuffles, then slices.

        Parameters
        ----------
        length : int

        Returns
        -------
        str — password with no repeated characters
        """
        pool   = list(dict.fromkeys(self._pool()))  # deduplicate while preserving order
        if length > len(pool):
            raise ValueError(
                f"Non-duplicate length {length} exceeds available unique "
                f"characters ({len(pool)}). Enable more character types.")
        rng = secrets.SystemRandom()
        rng.shuffle(pool)                           # secure shuffle
        return "".join(pool[:length])               # take first `length` characters

    def strength(self, password: str) -> dict:
        """
        Score a password's strength through a loop of progressive checks.

        Checks performed (in order):
          1. Length scoring         — up to 30 pts
          2. Uppercase presence     — 10 pts
          3. Lowercase presence     — 10 pts
          4. Digit presence         — 10 pts
          5. Special char presence  — 20 pts
          6. No repeated chars      — 10 pts
          7. No keyboard walks      — checked via loop over _KEYBOARD_WALKS
          8. Not in rockyou.txt     — 10 pts (silently skipped if db not loaded)

        Parameters
        ----------
        password : str

        Returns
        -------
        dict:
            'score'    : int   (0–100)
            'label'    : str   ('Weak' | 'Fair' | 'Strong' | 'Very Strong')
            'feedback' : list  of improvement tip strings
        """
        score    = 0        # running score out of 100
        feedback = []       # improvement tips to show the user

        # ── Check 1: Length ────────────────────────────────────────────────────
        n = len(password)
        if n >= 16:
            score += 30                         # long password: full points
        elif n >= 12:
            score += 20                         # medium: partial points
        elif n >= 8:
            score += 10                         # short but acceptable
        else:
            feedback.append("Use at least 8 characters (12+ is better).")

        # ── Check 2–5: Character variety ───────────────────────────────────────
        # Loop over each character type and check if the password uses it
        checks = [
            (any(c in _PG_UPPER   for c in password), 10, "Add uppercase letters (A-Z)."),
            (any(c in _PG_LOWER   for c in password), 10, "Add lowercase letters (a-z)."),
            (any(c in _PG_DIGITS  for c in password), 10, "Add digits (0-9)."),
            (any(c in _PG_SPECIAL for c in password), 20, "Add special characters (!@#…) for a big boost."),
        ]
        for present, pts, tip in checks:        # loop: check each category
            if present:
                score += pts                    # category present — add points
            else:
                feedback.append(tip)            # category missing — add tip

        # ── Check 6: No repeated characters ────────────────────────────────────
        if len(set(password)) == len(password):
            score += 10                         # all unique characters
        else:
            feedback.append("Avoid repeating the same character.")

        # ── Check 7: No keyboard walk patterns ─────────────────────────────────
        # Loop over the _KEYBOARD_WALKS list looking for any substring match
        pwd_lower = password.lower()            # compare case-insensitively
        walk_found = False
        for walk in _KEYBOARD_WALKS:            # loop through every known pattern
            if walk in pwd_lower:               # substring check
                walk_found = True
                break                           # one match is enough to penalise
        if walk_found:
            feedback.append("Avoid keyboard patterns (e.g. 'qwerty', '12345').")
        else:
            score += 0                          # no bonus — just no penalty

        # ── Check 8: rockyou.txt database check ────────────────────────────────
        if _ROCKYOU_SET:                        # only run if database was loaded
            if pwd_lower in _ROCKYOU_SET:       # O(1) set lookup
                feedback.append("This password appears in known breach databases — avoid it!")
            else:
                score += 10                     # not in the database: bonus points
        else:
            score += 10                         # database unavailable: give benefit of doubt

        # ── Label ─────────────────────────────────────────────────────────────
        if score >= 80:
            label = "Very Strong"
        elif score >= 60:
            label = "Strong"
        elif score >= 40:
            label = "Fair"
        else:
            label = "Weak"

        return {"score": score, "label": label, "feedback": feedback}


# ══════════════════════════════════════════════════════════════════════════════
#  BRUTE-FORCE TIME ESTIMATOR  (used by Home page of crypto_gui.py)
# ══════════════════════════════════════════════════════════════════════════════

def estimate_crack_time(password: str) -> str:
    """
    Estimate the brute-force crack time for a password.

    Formula:
        combinations = charset_size ^ length
        seconds      = combinations / 2 / guesses_per_second   (average case)

    Assumed speed: 1 billion guesses per second (offline GPU attack).

    Returns a human-readable string such as '~3.2 years' or 'instantly'.
    """
    if not password:
        return "—"                              # empty input — no estimate

    # Determine the effective character set size
    charset = 0
    if any(c in _PG_LOWER   for c in password): charset += 26  # a-z
    if any(c in _PG_UPPER   for c in password): charset += 26  # A-Z
    if any(c in _PG_DIGITS  for c in password): charset += 10  # 0-9
    if any(c in _PG_SPECIAL for c in password): charset += 32  # special chars

    if charset == 0:
        return "—"                              # all unknown characters

    combinations = charset ** len(password)     # total passwords of this length
    seconds = (combinations / 2) / 1_000_000_000  # average case at 1B guesses/sec

    # Convert seconds to the most appropriate human-readable unit
    if seconds < 1:
        return "instantly (< 1 second)"
    elif seconds < 60:
        return f"~{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"~{seconds/60:.1f} minutes"
    elif seconds < 86400:
        return f"~{seconds/3600:.1f} hours"
    elif seconds < 365.25 * 86400:
        return f"~{seconds/86400:.1f} days"
    elif seconds < 100 * 365.25 * 86400:
        return f"~{seconds/(365.25*86400):.1f} years"
    elif seconds < 1_000_000 * 365.25 * 86400:
        m = seconds / (1_000_000 * 365.25 * 86400)
        return f"~{m:.1f} million years"
    else:
        return "longer than the age of the universe"


# ══════════════════════════════════════════════════════════════════════════════
#  ROCKYOU LOADER  (also exposed for the GUI's Home page)
# ══════════════════════════════════════════════════════════════════════════════

def load_rockyou(path: str = "rockyou.txt") -> set:
    """
    Public wrapper for _load_rockyou().
    Called by the GUI's HomePage to get the breach database set.
    Returns the already-loaded set if rockyou was loaded at import time.
    """
    if _ROCKYOU_SET:
        return _ROCKYOU_SET                     # already loaded — reuse it
    return _load_rockyou(path)                  # try to load now


# # ══════════════════════════════════════════════════════════════════════════════
# #  QUICK SELF-TEST
# # ══════════════════════════════════════════════════════════════════════════════

# if __name__ == "__main__":

#     SEP = "=" * 60
#     print(SEP)
#     print("  crypto_lib.py (built-ins edition) — Self-Test")
#     print(SEP)

#     # Base64
#     print("\n[1] Base64")
#     raw = b"Hello, built-ins!"
#     assert base64_decode(base64_encode(raw)) == raw
#     print("    PASS")

#     # Hex
#     print("\n[2] Hex")
#     assert hex_decode(hex_encode(raw)) == raw
#     print("    PASS")

#     # URL
#     print("\n[3] URL  (includes Arabic)")
#     url_raw = "Hello World! مرحبا price=100$"
#     assert url_decode(url_encode(url_raw)) == url_raw
#     print("    PASS")

#     # SHA-256
#     print("\n[4] SHA-256")
#     assert sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb924" \
#                                "27ae41e4649b934ca495991b7852b855"
#     print("    PASS")

#     # SHA-512
#     print("\n[5] SHA-512")
#     assert sha512_hex(b"").startswith("cf83e1357eefb8bd")
#     print("    PASS")

#     # Salted Hash
#     print("\n[6] Salted Hash")
#     r = salted_hash("test_password")
#     assert salted_hash_verify("test_password", r["salt"], r["hash"])
#     assert not salted_hash_verify("wrong", r["salt"], r["hash"])
#     print("    PASS")

#     if _CRYPTO_OK:
#         msg = b"Test message for crypto"
#         iv16 = os.urandom(16)
#         iv8  = os.urandom(8)

#         # AES
#         print("\n[7] AES")
#         aes = AES(os.urandom(32))
#         for m in ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']:
#             ct = aes.encrypt(msg, mode=m, iv=iv16)
#             pt = aes.decrypt(ct,  mode=m, iv=iv16)
#             assert pt == msg, f"AES {m} failed"
#             print(f"    {m}: PASS")
#         gcm = aes.encrypt(msg, mode='GCM', iv=os.urandom(12))
#         pt  = aes.decrypt(gcm['ciphertext'], mode='GCM',
#                           iv=base64_decode(gcm['iv']),
#                           tag=base64_decode(gcm['tag']))
#         assert pt == msg
#         print("    GCM: PASS")

#         # DES
#         print("\n[8] DES")
#         des = DES(os.urandom(8))
#         for m in ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']:
#             ct = des.encrypt(msg, mode=m, iv=iv8)
#             pt = des.decrypt(ct,  mode=m, iv=iv8)
#             assert pt == msg, f"DES {m} failed"
#             print(f"    {m}: PASS")

#         # 3DES
#         print("\n[9] 3DES")
#         tdes = TripleDES(os.urandom(24))
#         for m in ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']:
#             ct = tdes.encrypt(msg, mode=m, iv=iv8)
#             pt = tdes.decrypt(ct,  mode=m, iv=iv8)
#             assert pt == msg, f"3DES {m} failed"
#             print(f"    {m}: PASS")

#         # RSA
#         print("\n[10] RSA")
#         rsa = RSA.generate(bits=1024)
#         ct  = rsa.encrypt(b"RSA test")
#         pt  = rsa.decrypt(ct)
#         assert pt == b"RSA test"
#         print("    Encrypt/Decrypt: PASS")
#         pub  = rsa_pub_hex(rsa)
#         priv = rsa_priv_hex(rsa)
#         rsa2 = rsa_from_hex(pub, priv)
#         assert rsa2.decrypt(ct) == b"RSA test"
#         print("    Key export/import: PASS")

#     else:
#         print("\n[7-10] Skipped — install 'cryptography': pip install cryptography")

#     # Password Generator
#     print("\n[11] PasswordGenerator")
#     pg  = PasswordGenerator()
#     pwd = pg.generate(length=20)
#     assert len(pwd) >= 20
#     r   = pg.strength(pwd)
#     assert r["score"] >= 0
#     print(f"    Generated: {pwd}")
#     print(f"    Score: {r['score']}/100 ({r['label']})")
#     print("    PASS")

#     print(f"\n{SEP}")
#     print("  All tests PASSED")
#     print(SEP)