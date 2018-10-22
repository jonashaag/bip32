import bip32utils.Base58
import pytest

import bip32

DATA = '''
m/44'/60'/0'/0/0	bb2Ca357e5780141f34500D43E492bEe15531211	02eed2a172ed2c25ffa74d10db6b37987b508c7129113297cba1be7466191211b1	17b95359ef2a332fa917507b5cafa06c3998d0451c7916fded9c923a7f8b866b
m/44'/60'/0'/0/1	Ae9a6d7E0a453344d6778081D34644E1aCE82E37	023eacf3d654494ea7155504020c2cbf6ea98f617780626e1cf86bca5602a064a4	21f188c09a4bbf90904cdaeb8d024baa4b8be0a2980cfd4d7c8648e55e304c3f
m/44'/60'/0'/0/2	E197D3d79e85644f657F60CD6912F30A365b76B8	027f9df9e79e3ffa0c48bda52a3d5874bdee9ebe5b6f7631e3d4dd21cf004e6c9d	e785446f88f0c87c1b06fe0731f7ac5759b29f188019960546e65d9cbaccde00

m/44'/0'/0'/0/0	18bkaWvgTST8vJb2LgdBueo6sP4eoF99Ve	02c1aeef761a85c7cb0a5f7a75f7fa77fec505a88281d6000544a15223876c2865	L2t4wu4R5FZv6jEkztwjDwZRsuE7WFtiX7upkiq6nkFPcemdaZdk
m/44'/0'/0'/0/1	1LKKSR2Giwm9FZpZn4LDJo8pFcCsBKpiSC	02d8717f7e7cdc3669b983b707d700121f69b6063cf437039334a5b3babb2b3e3b	KwRjx5s8UPKYixtDAuYxWNxNYzZ7M6xwKMq1Dqu3ZAo8c1VEPSJW
m/44'/0'/0'/0/2	1BQannPT4K1AbH33qy4YYZpN8gBkBhFxbb	0395305c01697c8a2ffd17d4df5704d887fc66e00f5ddc51d5db7c32f087491873	Ky3JbpRUcTgyp5q1SDZT9hvkU1VXKSzUwr1wK5nc1YYrudYWqXaQ
'''
DATA = [l.split() for l in DATA.splitlines() if l.strip()]

masterkey = bip32.HDKey.from_mnemonic(
    'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when')


@pytest.mark.parametrize('bip32_path,native_address,pubkey,privkey', DATA)
def test(bip32_path, native_address, pubkey, privkey):
    try:
        privkey = bytes.fromhex(privkey)
    except:
        privkey = bip32utils.Base58.check_decode(privkey)[1:-1]
    pubkey = bytes.fromhex(pubkey)
    derived = masterkey.derive_path(bip32_path)
    assert derived.bip32_path == bip32_path
    assert derived.bip44_address.lower() == native_address.lower()
    if "60'" in bip32_path:
        assert derived.eth_address.lower() == native_address.lower()
    else:
        assert derived.btc_address == native_address
    assert derived.public_key_bytes == pubkey
    assert derived.private_key_bytes == privkey
