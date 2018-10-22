from distutils.core import setup

setup(
    name='bip32',
    version='1.0',
    author='Jonas Haag',
    author_email='jonas@lophus.org',
    url='https://github.com/jonashaag/bip32',
    license='ISC',
    description="Python BIP32 implementation",
    py_modules=['bip32'],
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    install_requires=['mnemonic', 'bip32utils'],
)
