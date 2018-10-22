from bip32utils import BIP32_HARDEN, BIP32Key
from mnemonic import Mnemonic
from sha3 import keccak_256


class hardened(str):
    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return super().__eq__(other)


class HDKey(object):
    @classmethod
    def from_mnemonic(cls, *args, **kwargs):
        return cls.from_entropy(Mnemonic.to_seed(*args, **kwargs))

    @classmethod
    def from_entropy(cls, entropy, *args, **kwargs):
        return cls(BIP32Key.fromEntropy(entropy), *args, **kwargs)

    def __init__(self, _bip32utils_key: bytes, _bip32_path: list = ()):
        self._bip32utils_key = _bip32utils_key
        self._bip32_path = _bip32_path or []

    def derive_path(self, bip32_path):
        if isinstance(bip32_path, str):
            bip32_path = bip32_path.split('/')
            assert bip32_path[0] == 'm', "BIP 32 path must start with 'm/'"
            bip32_path = [
                hardened(s[:-1]) if s[-1] == "'" else s for s in bip32_path[1:]
            ]

        next_index = bip32_path.pop(0)
        is_hardened = isinstance(next_index, hardened)
        next_derivative = self.__class__(
            self._bip32utils_key.CKDpriv(
                int(next_index) | (is_hardened and BIP32_HARDEN or 0)),
            self._bip32_path + [next_index])
        if not bip32_path:
            return next_derivative
        else:
            return next_derivative.derive_path(bip32_path)

    @property
    def bip32_path(self):
        return 'm/' + '/'.join(f"{i}'" if isinstance(i, hardened) else f"{i}"
                               for i in self._bip32_path)

    @property
    def btc_address(self):
        return self._bip32utils_key.Address()

    @property
    def btc_address_bytes(self):
        return b'\x00' + self._bip32utils_key.Identifier()

    @property
    def eth_address(self):
        return self.eth_address_bytes.hex()

    @property
    def eth_address_bytes(self):
        return keccak_256(self._bip32utils_key.K.to_string()).digest()[12:]

    @property
    def bip44_address(self):
        assert len(self._bip32_path) >= 3 and self._bip32_path[0] == hardened(
            44) and isinstance(
                self._bip32_path[1],
                hardened), f'{self.bip32_path} is not a valid BIP 44 path'
        try:
            network = {
                '0': 'btc',
                '60': 'eth',
            }[str(self._bip32_path[1])]
            return getattr(self, f'{network}_address')
        except KeyError:
            raise NotImplementedError(
                f'Unknown network with ID {self._bip32_path[1]}')

    @property
    def public_key_bytes(self):
        return self._bip32utils_key.PublicKey()

    @property
    def private_key_bytes(self):
        return self._bip32utils_key.PrivateKey()
