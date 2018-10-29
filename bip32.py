from binascii import hexlify

from bip32utils import BIP32_HARDEN, BIP32Key
from mnemonic import Mnemonic
from sha3 import keccak_256


def hardened(n):
    if is_hardened(n):
        raise ValueError('%d is already hardened' % n)
    return n | BIP32_HARDEN


def is_hardened(n):
    return n & BIP32_HARDEN


def parse_hardened_str(s):
    if s[-1] == "'":
        return hardened(int(s[:-1]))
    else:
        return int(s)


def format_hardened(n):
    if is_hardened(n):
        return "%d'" % (n & ~BIP32_HARDEN)
    else:
        return "%d" % n


class HDKey(object):
    @classmethod
    def from_mnemonic(cls, *args, **kwargs):
        return cls.from_entropy(Mnemonic.to_seed(*args, **kwargs))

    @classmethod
    def from_entropy(cls, entropy, *args, **kwargs):
        return cls(BIP32Key.fromEntropy(entropy), *args, **kwargs)

    def __init__(self, _bip32utils_key, _bip32_path=()):
        self._bip32utils_key = _bip32utils_key
        self._bip32_path = _bip32_path or []

    def __eq__(self, other):
        return isinstance(
            other, self.
            __class__) and self.private_key_bytes == other.private_key_bytes

    def derive_path(self, bip32_path):
        if isinstance(bip32_path, str):
            bip32_path = bip32_path.split('/')
            assert bip32_path.pop(0) == 'm', "BIP 32 path must start with 'm/'"
            bip32_path = [parse_hardened_str(s) for s in bip32_path]

        next_derivative = self.derive_single(bip32_path.pop(0))
        if not bip32_path:
            return next_derivative
        else:
            return next_derivative.derive_path(bip32_path)

    def derive_single(self, idx):
        if not isinstance(idx, int):
            idx = parse_hardened_str(idx)
        return self.__class__(
            self._bip32utils_key.CKDpriv(idx), self._bip32_path + [idx])

    @property
    def bip32_path(self):
        return 'm/' + '/'.join(map(format_hardened, self._bip32_path))

    @property
    def btc_address(self):
        return self._bip32utils_key.Address()

    @property
    def btc_address_bytes(self):
        return b'\x00' + self._bip32utils_key.Identifier()

    @property
    def eth_address(self):
        return hexlify(self.eth_address_bytes).decode('ascii')

    @property
    def eth_address_bytes(self):
        return keccak_256(self._bip32utils_key.K.to_string()).digest()[12:]

    @property
    def bip44_address(self):
        assert len(self._bip32_path) >= 3 and self._bip32_path[0] == hardened(
            44) and is_hardened(
                self._bip32_path[1]
            ), '%r is not a valid BIP 44 path' % self.bip32_path
        try:
            network = {
                0 | BIP32_HARDEN: 'btc',
                60 | BIP32_HARDEN: 'eth',
            }[self._bip32_path[1]]
            return getattr(self, '%s_address' % network)
        except KeyError:
            raise NotImplementedError('Unknown network with ID %s' %
                                      format_hardened(self._bip32_path[1]))

    @property
    def public_key_bytes(self):
        return self._bip32utils_key.PublicKey()

    @property
    def private_key_bytes(self):
        return self._bip32utils_key.PrivateKey()

    def iter_children(self, start_index=0, end_index='kind'):
        if end_index == 'kind':
            if is_hardened(start_index):
                end_index = hardened(2**31 - 1)
            else:
                end_index = 2**31 - 1
        elif end_index == 'all':
            end_index = hardened(2**31 - 1)
        for i in range(start_index, end_index + 1):
            yield i, self.derive_single(i)
