# python-pgp_passtool: OpenPGP Passphrase Tool

This is a library and a CLI tool for manipulating the passphrase and secret
key encryption of a RFC4880 OpenPGP Transferable Private Key.


## Dependencies

You will need:

   * Python 2.7 or 3.x (not sure which 3.x)
   * python-pgpdump
   * cryptography


## Shell examples:

    # Get some instructions
    $ python -m pgp_passtool
    ...

    # Interactive passphrase changing
    $ python -m pgp_passtool key.pgp new-key.pgp  # Prompts for passphrases
    ...

    # Pipeline: strip the passphrase and ask GnuPG to parse the result
    $ (echo "my old passphrase"; echo; cat key.pgp) \
        python -m pgp_passtool - \
        gpg --list-packets
    ...

 
## Code example:

    from pgp_passtool import change_passphrase

    new_key_binary = change_passphrase(old_key_binary, old_pw, new_pw)

