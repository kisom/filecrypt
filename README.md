## filecrypt

This is an encryption utility designed to backup a set of files. The
files are packed into a gzipped tarball in-memory, and this is encrypted
using NaCl via a scrypt-derived key.

It derives from the `passcrypt` utility in the
[cryptutils](https://github.com/kisom/cryptutils/), and was written as
an example for the book "Practical Cryptography with Go."


## Motivations

This program arose from the need to backup and archive files on
removeable media that may be restored on multiple platforms. There
aren't any well-supported and readily available disk encryption systems
that work in this type of environment, and using GnuPG requires GnuPG,
the archiver, and a suitable decompression program to be provided. This
program is statically built and can run standalone on all the needed
platforms.


## Security model

This program assumes that an attacker does not currently have access
to either the machine the archive is generated on, or on the machine
it is unpacked on. It is intended for medium to long-term storage of
sensitive data at rest on removeable media that may be used to load data
onto a variety of platforms (Windows, OS X, Linux, OpenBSD), where the
threat of losing the storage medium is considerably higher than losing a
secured laptop that the archive is generated on.

Key derivation is done by pairing a password with a randomly-chosen
256-bit salt using the scrypt parameters N=2^20, r=8, p=1. This makes
it astronomically unlikely that the same key will be derived from the
same passphrase. The key is used as a NaCl secretbox key; the nonce for
encryption is randomly generated. It is thought that this will be highly
unlikely to cause nonce reuse issues.

The primary weaknesses might come from an attack on the passphrase or
via cryptanalysis of the ciphertext. The ciphertext is produced using
NaCl appended to a random salt, so it is unlikely this will produce any
meaningful information. One exception might be if this program is used
to encrypt a known set of files, and the attacker compares the length of
the archive to a list of known file sizes.

An attack on the passphrase will most likely come via a successful
dictionary attack. The large salt and high scrypt parameters will
deter attackers without the large resources required to brute force
this. Dictionary attacks will also be expensive for these same reasons.


## Usage

```
filecrypt [-h] [-o filename] [-q] [-t] [-u] [-v] [-x] files...

        -h              Print this help message.

        -o filename     The filename to output. If an archive is being built,
                        this is the filename of the archive. If an archive is
                        being unpacked, this is the directory to unpack in.
                        If the tarball is being extracted, this is the path
                        to write the tarball.

                        Defaults:
                                   Pack: files.enc
                                 Unpack: .
                                Extract: files.tgz

        -q              Quiet mode. Only print errors and password prompt.
                        This will override the verbose flag.

	-t		List files in the archive. This acts like the list
			flag in tar.

        -u              Unpack the archive listed on the command line. Only
                        one archive may be unpacked.

        -v              Verbose mode. This acts like the verbose flag in
                        tar.

        -x              Extract a tarball. This will decrypt the archive, but
                        not decompress or unpack it.

Examples:
        filecrypt -o ssh.enc ~/.ssh
                Encrypt the user's OpenSSH directory to ssh.enc.

        filecrypt -o backup/ -u ssh.enc
                Restore the user's OpenSSH directory to the backup/
                directory.

        filecrypt -u ssh.enc
                Restore the user's OpenSSH directory to the current directory.

```


## License

filecrypt is released under the ISC license.

```
Copyright (c) 2015 Kyle Isom <kyle@tyrfingr.is>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above 
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. 
```

