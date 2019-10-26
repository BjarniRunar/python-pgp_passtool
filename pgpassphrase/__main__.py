#!/usr/bin/python
"""\
pgpassphrase - Change passphrases on an OpenPGP Transferable Secret Key.

Usage examples:
    pgpassphrase [--fast] /path/to/key.pgp [/path/to/new-key.pgp]
    (echo oldpw; echo newpw; cat key.pgp) | pgpassphrase - |gpg --list-packets

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

if __name__ == "__main__":
    import sys
    from . import change_passphrase

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

        new_key = change_passphrase(old_key, old_pass, new_pass, fast)

        # If we get this far, we have new key material!
        out_fd = open(args[1], 'wb') if len(args) == 2 else sys.stdout
        if hasattr(out_fd, 'buffer'):
            out_fd = out_fd.buffer

        out_fd.write(new_key)
        out_fd.close()

    else:
        sys.stderr.write(__doc__)
        sys.exit(1)
