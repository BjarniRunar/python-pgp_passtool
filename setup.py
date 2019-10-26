from setuptools import setup

from pgp_passtool import __version__, __author__

classifiers = [
    'Development Status :: 4 - Beta',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: BSD License',
    'Programming Language :: Python',
    'Programming Language :: Python :: 3',
    'Topic :: Security :: Cryptography',
    'Topic :: Software Development :: Libraries :: Python Modules']

setup(
    name = 'pgp_passtool',
    version = __version__,
    author = __author__,
    license = 'BSD',
    description = 'OpenPGP Passphrase Tool (and library)',
    url = 'https://github.com/BjarniRunar/python-pgp_passtool',
    download_url = 'https://github.com/BjarniRunar/python-pgp_passtool/archive/v0.0.1.tar.gz',
    keywords = 'pgp gpg rfc2440 rfc4880 crypto cryptography',
    install_requires = ['pgpdump', 'cryptography'],
    classifiers = classifiers,
    packages = ['pgp_passtool'])
