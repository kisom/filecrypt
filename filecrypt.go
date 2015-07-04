package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/gokyle/readpass"
	"github.com/kisom/filecrypt/archive"
	"github.com/kisom/filecrypt/crypto"
)

var version = "1.0.0"

func dieIf(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}
}

var quiet bool

func print(s string) {
	if !quiet {
		fmt.Println(s)
	}
}

func printf(fmtstr string, args ...interface{}) {
	if !quiet {
		fmt.Printf(fmtstr, args...)
	}
}

func dieWith(fs string, args ...interface{}) {
	outStr := fmt.Sprintf("[!] %s\n", fs)
	fmt.Fprintf(os.Stderr, outStr, args...)
	os.Exit(1)
}

func main() {
	help := flag.Bool("h", false, "print a short usage message")
	lower := flag.Bool("l", false, "use the lower scrypt settings")
	out := flag.String("o", "", "output path")
	flag.BoolVar(&quiet, "q", false, "do not print any additional output")
	list := flag.Bool("t", false, "list files")
	unpack := flag.Bool("u", false, "unpack files instead of packing them")
	flag.BoolVar(&archive.Verbose, "v", false, "enable verbose logging")
	extract := flag.Bool("x", false, "extract .tgz from archive")
	flag.Parse()

	if *help || flag.NArg() == 0 {
		usage()
		return
	}

	if *lower {
		crypto.Iterations = crypto.IterationsLow
	}

	if *unpack && *extract {
		fmt.Fprintf(os.Stderr, "Only one of unpack or extract may be chosen.")
		os.Exit(1)
	}

	if *out == "" {
		if *unpack {
			*out = "."
		} else if *extract {
			*out = "files.tgz"
		} else {
			*out = "files.enc"
		}
	}

	var pass []byte
	var err error

	if !(*unpack || *extract || *list) {
		for {
			pass, err = readpass.PasswordPromptBytes("Archive password: ")
			dieIf(err)

			var confirm []byte
			confirm, err = readpass.PasswordPromptBytes("Confirm: ")
			dieIf(err)

			if !bytes.Equal(pass, confirm) {
				fmt.Println("Passwords don't match.")
				continue
			}

			crypto.Zero(confirm)
			break
		}
	} else {
		pass, err = readpass.PasswordPromptBytes("Archive password: ")
		dieIf(err)
	}

	start := time.Now()
	if *unpack || *extract || *list {
		if flag.NArg() != 1 {
			dieWith("only one file may unpacked at a time.")
		}

		print("Reading encrypted archive...")
		in, err := ioutil.ReadFile(flag.Arg(0))
		dieIf(err)

		print("Decrypting archive...")
		in, err = crypto.Open(pass, in)
		dieIf(err)

		if *unpack {
			print("Unpacking files...")
			err = archive.UnpackFiles(in, *out, true)
		} else if *list {
			err = archive.UnpackFiles(in, *out, false)
		} else {
			print("Extracting .tgz...")
			err = ioutil.WriteFile(*out, in, 0644)
		}
		dieIf(err)
	} else {
		print("Packing files...")
		fData, err := archive.PackFiles(flag.Args())
		dieIf(err)

		print("Encrypting archive...")
		fData, err = crypto.Seal(pass, fData)
		dieIf(err)

		print("Writing file...")
		err = ioutil.WriteFile(*out, fData, 0644)
		dieIf(err)
	}

	printf("Completed in %s.\n", time.Since(start))
}

func usage() {
	progName := filepath.Base(os.Args[0])
	fmt.Printf(`%s version %s, (c) 2015 Kyle Isom <kyle@tyrfingr.is>
Released under the ISC license.

Usage:
%s [-h] [-o filename] [-q] [-t] [-u] [-v] [-x] files...

	-h 		Print this help message.

	-o filename	The filename to output. If an archive is being built,
			this is the filename of the archive. If an archive is
			being unpacked, this is the directory to unpack in.
			If the tarball is being extracted, this is the path
			to write the tarball.

			Defaults:
				   Pack: files.enc
				 Unpack: .
				Extract: files.tgz

	-q		Quiet mode. Only print errors and password prompt.
			This will override the verbose flag.

	-t		List files in the archive. This acts like the list
			flag in tar.

	-u		Unpack the archive listed on the command line. Only
			one archive may be unpacked.

	-v		Verbose mode. This acts like the verbose flag in
			tar.

	-x		Extract a tarball. This will decrypt the archive, but
			not decompress or unpack it.

Examples:
	%s -o ssh.enc ~/.ssh
		Encrypt the user's OpenSSH directory to ssh.enc.

	%s -o backup/ -u ssh.enc
		Restore the user's OpenSSH directory to the backup/
		directory.

	%s -u ssh.enc
		Restore the user's OpenSSH directory to the current directory.

`, progName, version, progName, progName, progName, progName)
}
