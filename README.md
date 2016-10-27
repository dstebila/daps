Double-authentication-preventing signatures
===========================================

This software implements the double-authentication-preventing signature schemes H2[GQ], ID2[GQ], and H2[MR] from the following paper:

- Mihir Bellare, Bertram Poettering, and Douglas Stebila. **Deterring Certificate Subversion: Efficient Double-Authentication-Preventing Signatures**. *IACR Cryptology ePrint Archive*, Report 2016/1016. October, 2016.  [https://eprint.iacr.org/2016/1016](https://eprint.iacr.org/2016/1016).

What are double-authentication-preventing signatures?
-----------------------------------------------------

Double-authentication-preventing signatures (DAPS) were first proposed by Poettering and Stebila [[ESORICS 2014]](https://www.douglas.stebila.ca/research/papers/ESORICS-PoeSte14/), [[IJIS 2015]](https://www.douglas.stebila.ca/research/papers/IJIS-PoeSte15/).    In DAPS, the data to be signed is split into two portions: an *address* and a *payload*.  If a signer ever signs two messages with same address but different payloads, enough information is revealed to allow the signer's secret key to be recovered.  This motivates the signer to not sign multiple messages with the same address.

One potential application of DAPS is in public key infrastructures (PKIs).  Certificate authorities (CAs) sign certificates for domain names (or email addresses, or other things).  A common concern with the web PKI today is that certificate authorities might issue fraudulent certificates, possibly to due to subversion.  Suppose DAPS was used in a PKI, where the domain name is the DAPS address and the certificate body is DAPS payload.  DAPS would motivate a CA to never issue multiple certificates for the same domain name: If a CA ever issues two certificates for the same domain name, then DAPS would allow the CA's private key to be discovered, effectively destroying the CA's business.  This gives the CA a compelling argument to resist subversion.

This software
-------------

This software implements three new double-authentication-preventing signatures schemes (H2[GQ], ID2[GQ], and H2[MR]) as well as the original DAPS scheme of Poettering and Stebila (PS).  The H2[GQ] and ID2[GQ] DAPS schemes are constructed from the GQ identification scheme; the H2[MR] DAPS scheme is based on the MR identification scheme (with minor changes).  Details on the constructions can be found in the paper.

Building
--------

The software is plain C.  Compilation has been tested using gcc on Ubuntu 16.04.1 and clang on Mac OS X 10.11.6, and macOS 10.12.  The software uses some routines from OpenSSL's libcrypto, so you will need to have OpenSSL installed.

### To compile on Ubuntu:

	sudo apt-get install make gcc libssl-dev
	make

### To compile on macOS using brew:

You will need to have installed the Xcode developer tools, including the command-line programs.  You will also need a recent copy of OpenSSL.  You can install OpenSSL using the [brew](http://brew.sh) package manager.

	brew install openssl
	make
	
You can also download and compile OpenSSL yourself following the instructions on the [OpenSSL website](https://www.openssl.org/).  In this case, you will need to edit the `Makefile` to point to your copy of OpenSSL or compile with `make OPENSSL_DIR=/path/to/your/openssl`.

Running
-------

### To run the DAPS test harness:

	./main

### To do performance testing:

	./performance

For most accurate results:

- Disable hyperthreading a.k.a. hardware multithreading
	- Linux instructions: [http://bench.cr.yp.to/supercop.html](http://bench.cr.yp.to/supercop.html)
	- Mac OS X instructions: Instruments → Preferences → CPUs → uncheck "Hardware Multi-Threading" ([http://forums.macrumors.com/showthread.php?t=1484684](http://forums.macrumors.com/showthread.php?t=1484684))
- Disable TurboBoost
	- Linux instructions: [http://bench.cr.yp.to/supercop.html](http://bench.cr.yp.to/supercop.html)
	- Max OS X: use [http://www.rugarciap.com/turbo-boost-switcher-for-os-x/](http://www.rugarciap.com/turbo-boost-switcher-for-os-x/)
- Run when the computer is idle (e.g., shut down all other applications, disable network access if possible, etc.).

License
-------

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or distribute this software, either in source code form or as a compiled binary, for any purpose, commercial or non-commercial, and by any means.

See the file `LICENSE.txt` for complete information.

Acknowledgements
----------------

MB was supported in part by NSF grants CNS-1228890 and CNS-1526801, a gift from Microsoft corporation and ERC Project ERCC (FP7/615074). BP was supported by ERC Project ERCC (FP7/615074).  DS was supported in part by Australian Research Council (ARC) Discovery Project grant DP130104304 and Natural Sciences and Engineering Research Council of Canada (NSERC) Discovery grant RGPIN-2016-05146.
