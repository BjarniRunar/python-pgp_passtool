"""\
pgp_passtool - Change an OpenPGP Transferable Secret Key's passphrase

Usage examples:
    python -m pgp_passtool [--fast] /path/to/key.pgp [/path/to/new-key.pgp]
    (echo oldpw; echo; cat key.pgp) |python -m pgp_passtool - |gpg --list-packets

This tool will read one or two passphrases from standard input (old and new),
and then use that to re-encrypt the secret key material. The new key material
is sent to stdout if no output file is specifed.

If only one passphrase is provided, the output will be an unprotected key.

If the input filename is a single dash (-), read the input key material from
standard input after both passphrases have been read. If the flag --fast is
present, we will assume the new passphrase already has high entropy and use
fast (potentially less secure) key derivation.

If the passphrase has non-ASCII characters in it and was not encoded as
UTF-8, you can set the PGPASSWD_CHARSET environment variable to something
like 'latin-1' to allow things to decrypt. The variable is ignored when
encrypting secret keys, then passphrases are always encoded UTF-8.

The tool will noisily crash on inputs it cannot handle, or if the passphrase
is incorrect. It won't overwrite/create the output file in such cases.

NOTE: This implementation is incomplete and only handles the common, modern
      schemes for encrypting secret key material. YMMV. :-)
"""
import base64
import hashlib
import os
import pgpdump
import sys

from pgpdump.utils import get_mpi, get_int2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

__author__ = 'Bjarni R. Einarsson <bre@mailpile.is>'
__version__ = '0.0.1'


get_random_bytes = os.urandom


def UNUSED_get_random_bytes(count):
    return bytes(b'A' * count)


def _monkey_patch_pgpdump():
    """
    Monkey-patch pgpdump to handle ECC keys. This tries to patch things
    in a backwards compatible way, so if our underlying pgpdump grows
    support for these things, this just becomes a no-op.
    """
    # Add Algorithm 22 to the lookup table
    if 22 not in pgpdump.packet.AlgoLookup.pub_algorithms:
        pgpdump.packet.AlgoLookup.pub_algorithms[22] = 'EdDSA'

    # Handle elliptic-curve public keys
    orig_pkm = pgpdump.packet.PublicKeyPacket.parse_key_material
    def _patched_pkm(self, offset):
        try:
            return orig_pkm(self, offset)
        except:
            if self.raw_pub_algorithm not in (18, 22):
                raise
            self.pub_algorithm_type = "ecc"
            offset += self.data[offset] + 1  # Skip OID
            self.key_value, offset = get_mpi(self.data, offset)
            if self.raw_pub_algorithm == 18:
                offset += self.data[offset] + 1  # Skip KDF
            return offset
    pgpdump.packet.PublicKeyPacket.parse_key_material = _patched_pkm

    # Handle elliptic-curve secret keys
    orig_pks = pgpdump.packet.SecretKeyPacket.parse_private_key_material
    def _patched_pks(self, offset):
        try:
            return orig_pks(self, offset)
        except:
            if self.raw_pub_algorithm not in (18, 22):
                raise
        self.pub_algorithm_type = "ecc"
        self.exponent_x, offset = get_mpi(self.data, offset)
        return offset
    pgpdump.packet.SecretKeyPacket.parse_private_key_material = _patched_pks


def s2k(string, hash_algo, cipher_algo, salt='', iter_code=None):
    """
    This implements a subset of the OpenPGP S2K (string-to-key) algorithm.
    Raises ValueError or KeyError for invalid inputs.
    The GNU extensions are not supported.

    >>> from pgpy.packet.fields import String2Key, String2KeyType
    >>> ref = String2Key()
    >>> ref.specifier = String2KeyType.Simple
    >>> ref.encalg = 7
    >>> ref.halg = 2
    >>> ref.usage = 254
    >>> base64.b64encode(ref.derive_key('hello'))
    'qvTGHdzF6KLavt4PO0gs2Q=='
    >>> base64.b64encode(s2k('hello', 2, 7))
    'qvTGHdzF6KLavt4PO0gs2Q=='

    >>> base64.b64encode(s2k('hello', 2, 8, salt='12345678'))
    'JmySvg6Y0VpstW7OfQP01BqkL7dxbFsW'

    >>> base64.b64encode(s2k('hello', 2, 8, salt='87654321', iter_code=1))
    'rC70dvVsIMBOfJIsSAhgPmrwKQSGw2hg'

    >>> ref.specifier = String2KeyType.Iterated
    >>> ref.salt = bytearray(b'\x19#J\xb4\x11\x9d\xee;')
    >>> ref.count = 249
    >>> a = base64.b64encode(ref.derive_key('testing'))
    >>> print(a)
    Ou7sJzQRfMXgz7c5O0kpaQ==
    >>> b = base64.b64encode(s2k('testing', 2, 7, ref.salt, 249))
    >>> print(b)
    Ou7sJzQRfMXgz7c5O0kpaQ==
    """
    hash_cls, hash_bits = {
         1: (hashlib.md5,    128),
         2: (hashlib.sha1,   160),
         8: (hashlib.sha256, 256),
         9: (hashlib.sha384, 384),
        10: (hashlib.sha512, 512),
        11: (hashlib.sha224, 224)
        }[hash_algo]

    bits_needed = {
         1: 128,  # IDEA,
         2: 192,  # 3DES,
         3: 128,  # CAST5,
         7: 128,  # AES
         8: 192,  # AES
         9: 256,  # AES
        10: 256,  # Twofish
        }[cipher_algo]

    if len(salt) not in (0, 8):
        raise ValueError('Invalid salt')
    data = bytearray(salt) + bytearray(string)

    contexts_needed = 1 + ((bits_needed-1) // hash_bits)
    contexts = [hash_cls(b'\x00' * i) for i in range(0, contexts_needed)]
    if iter_code is not None:
        octet_count = (16 + (iter_code & 15)) << ((iter_code >> 4) + 6)
    else:
        octet_count = len(data)

    hcount = int(octet_count / len(data))
    hleft = octet_count - (hcount * len(data))
    key = b''
    for i, ctx in enumerate(contexts):
        for c in range(0, hcount):
            ctx.update(data)
        ctx.update(data[:hleft])
        key += ctx.digest()

    return key[:(bits_needed // 8)]


class MutableSecretKeyPacket(pgpdump.packet.SecretKeyPacket):
    @classmethod
    def copy(cls, packet):
        return cls(packet.raw, packet.name, packet.new, packet.data)

    def get_s2k_offset(self):
        return super(pgpdump.packet.SecretKeyPacket, self).parse()

    def set_secret_key_data(self, s2k_id, packet_data):
        offset = self.get_s2k_offset()
        self.data = bytearray(self.data[:offset])
        self.data.append(s2k_id)
        if s2k_id == 0:
            checksum = sum(packet_data) % 65536
            self.data += packet_data
            self.data.append(checksum // 256)
            self.data.append(checksum % 256)
        elif s2k_id in (254, 255):
            self.data += packet_data
        else:
            raise ValueError('Unknown s2k_id: %d' % s2k_id)
        self.parse()


def _unlock_secret_key(packet, passphrase, decoding_charset):
    if packet.s2k_id == 0:
        return packet
    if packet.s2k_id not in (254, 255):
        raise ValueError('Unhandled s2k usage mode: %s' % packet.s2k_id)

    new_packet = MutableSecretKeyPacket.copy(packet)
    s2k_offset = new_packet.get_s2k_offset()
    assert(packet.s2k_id == new_packet.data[s2k_offset])

    s2k_calg = new_packet.data[s2k_offset+1]
    s2k_type = new_packet.data[s2k_offset+2]
    s2k_hash = new_packet.data[s2k_offset+3]
    s2k_salt = ''
    s2k_count = None
    if s2k_type == 1:
        s2k_salt = new_packet.data[s2k_offset+4:s2k_offset+12]
        enc_offset = s2k_offset + 12
    elif s2k_type == 3:
        s2k_salt = new_packet.data[s2k_offset+4:s2k_offset+12]
        s2k_count = new_packet.data[s2k_offset+12]
        enc_offset = s2k_offset + 13
    else:
        enc_offset = s2k_offset + 4
    enc_offset += len(packet.s2k_iv)
    encrypted_data = new_packet.data[enc_offset:]

    enc_pass = passphrase.encode(decoding_charset)
    key = s2k(enc_pass, s2k_hash, s2k_calg, s2k_salt, s2k_count)
    decryptor = Cipher({
            # FIXME: Add more?
            7: algorithms.AES,
            8: algorithms.AES,
            9: algorithms.AES
        }[s2k_calg](key),
        modes.CFB(bytes(packet.s2k_iv)),
        default_backend()).decryptor()

    decrypted_data = bytearray(
        decryptor.update(bytes(encrypted_data)) + decryptor.finalize())
    if packet.s2k_id == 254:
        secret_data = decrypted_data[:-20]
        ccs = hashlib.sha1(secret_data).digest()
        dcs = decrypted_data[-20:]
    elif packet.s2k_id == 255:
        secret_data = decrypted_data[:-2]
        ccs = sum(bytearray(secret_data)) % 65536
        dcs = get_int2(decrypted_data[-2:], 0)

    if ccs != dcs:
        raise ValueError('Bad passphrase, failed to decrypt.')

    new_packet.set_secret_key_data(0, secret_data) 
    return new_packet


def _lock_secret_key(packet, new_pass, fast):
    if packet.s2k_id != 0:
        raise ValueError('Cannot lock an already locked key')

    new_packet = MutableSecretKeyPacket.copy(packet)
    s2k_offset = new_packet.get_s2k_offset()
    assert(packet.s2k_id == new_packet.data[s2k_offset])

    s2k_id = 254
    secret_data = new_packet.data[s2k_offset+1:-2]
    secret_data += hashlib.sha1(secret_data).digest()

    enc_pass = new_pass.encode('utf-8')
    s2k_salt = get_random_bytes(8)
    assert(len(s2k_salt) == 8)
    s2k_type = 3  # Salted and Iterated
    s2k_hash = 2  # SHA1
    s2k_calg = 7  # AES-128
    s2k_iter = 1 if fast else 249
    aes128_iv = get_random_bytes(16)
    encryptor = Cipher(
        algorithms.AES(s2k(enc_pass, s2k_hash, s2k_calg, s2k_salt, s2k_iter)),
        modes.CFB(aes128_iv),
        default_backend()).encryptor()

    encrypted_data = bytearray(
        encryptor.update(bytes(secret_data)) + encryptor.finalize())

    new_packet.set_secret_key_data(s2k_id, (
        bytearray([s2k_calg, s2k_type, s2k_hash]) +
        s2k_salt +
        bytearray([s2k_iter]) +
        aes128_iv +
        encrypted_data))

    return new_packet


def _pgp_header(_type, body_length):
    if body_length < 192:
        return bytearray([_type+0xC0, body_length])
    elif body_length < 8384:
        return bytearray([
            _type+0xC0,
            (body_length-192) // 256 + 192,
            (body_length-192) % 256])
    else:
        return bytearray([
            _type+0xC0, 255,
            body_length // (1<<24),
            body_length // (1<<16) % 256,
            body_length // (1<<8) % 256,
            body_length % 256])


def change_passphrase(
        keydata, old_pass, new_pass='',
        fast=False, decoding_charset='utf-8'):
    """
    Accepts a PGP key (armored or binary) and attempt to change the
    passphrase of any secret keys within.

    If new_pass is false (blank or None), the output will be an
    unprotected key. If fast is True, the new passphrase is assumed to
    already have high entropy and we use a minimal number of iterations
    when deriving the actual encryption key.

    Returns the new key in binary form, raises an exception on error.
    """
    keydata = bytes(keydata)
    if b'-----BEGIN PGP' in keydata:
        packet_iter = pgpdump.AsciiData(keydata).packets()
    else:
        packet_iter = pgpdump.BinaryData(keydata).packets()

    try:
        # Ensure correct encoding on Python 2
        if not isinstance(old_pass, unicode):
            old_pass = old_pass.decode('utf-8')
        if not isinstance(new_pass, unicode):
            new_pass = new_pass.decode('utf-8')
    except NameError:
        pass

    output = []
    for packet in packet_iter:
        if packet.raw in (5, 7):
            packet = _unlock_secret_key(packet, old_pass, decoding_charset)
            if new_pass:
                packet = _lock_secret_key(packet, new_pass, fast)
        if packet is not None:
            output.append(packet)

    newkey = b''
    for p in output:
        newkey += _pgp_header(p.raw, len(p.data)) + p.data

    return newkey


def main():
    import os
    import sys

    decoding_charset = os.getenv('PGPASSWD_CHARSET') or 'utf-8'

    if len(sys.argv) in (2, 3, 4):
        fast = '--fast' in sys.argv
        args = [a for a in sys.argv[1:] if a != '--fast'] 

        if args[0] != '-':
            old_key = open(args[0], 'rb').read()

        from getpass import getpass
        if not sys.stdin.isatty():
            getpass = lambda p: sys.stdin.readline().split('\n')[0]
        old_pass = getpass('Old passphrase: ')
        new_pass = getpass('New passphrase: ')

        if args[0] == '-':
            old_key = sys.stdin.read()

        new_key = change_passphrase(old_key, old_pass, new_pass,
                fast=fast,
                decoding_charset=decoding_charset)

        # If we get this far, we have new key material!
        out_fd = open(args[1], 'wb') if len(args) == 2 else sys.stdout
        if hasattr(out_fd, 'buffer'):
            out_fd = out_fd.buffer

        out_fd.write(new_key)
        out_fd.close()

    else:
        sys.stderr.write(__doc__)
        sys.exit(1)


_monkey_patch_pgpdump()

if __name__ == "__main__":
    import doctest
    results = doctest.testmod(optionflags=doctest.ELLIPSIS)
    print('%s' % (results, ))
    if results.failed:
        sys.exit(1)
