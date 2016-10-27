##############################################################################################
# DAPS: double-authentication preventing signatures
#
# Based on the paper:
#     Mihir Bellare, Bertram Poettering, and Douglas Stebila.
#     Deterring Certificate Subversion: Efficient Double-Authentication-Preventing Signatures.
#     IACR Cryptology ePrint Archive, Report 2016/1016. October, 2016.
#     https://eprint.iacr.org/2016/1016
#
# Software originally developed by Douglas Stebila.
#
# Released into the public domain; see LICENSE.txt for details.
##############################################################################################

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	OPENSSL_DIR=/usr
endif
ifeq ($(UNAME_S),Darwin)
	OPENSSL_DIR=/usr/local/opt/openssl
endif

CC=cc

OPENSSL_INCLUDE_DIR=$(OPENSSL_DIR)/include
OPENSSL_LIB_DIR=$(OPENSSL_DIR)/lib

OFILES = bn_extra.o id_gq.o daps_h2_gq.o daps_id2_gq.o daps_h2_mr.o tdf_ps.o daps_ps.o

CFLAGS=-O3 -std=c11 -Wall -Wextra -Wpedantic -I$(OPENSSL_INCLUDE_DIR) 
LDFLAGS=-L$(OPENSSL_LIB_DIR) -lcrypto

all:
	$(CC) $(CFLAGS) -c bn_extra.c -I$(OPENSSLDIR)/include
	$(CC) $(CFLAGS) -c id_gq.c -I$(OPENSSLDIR)/include
	$(CC) $(CFLAGS) -c daps_h2_gq.c -I$(OPENSSLDIR)/include
	$(CC) $(CFLAGS) -c daps_id2_gq.c -I$(OPENSSLDIR)/include
	$(CC) $(CFLAGS) -c daps_h2_mr.c -I$(OPENSSLDIR)/include
	$(CC) $(CFLAGS) -c tdf_ps.c -I$(OPENSSLDIR)/include
	$(CC) $(CFLAGS) -c daps_ps.c -I$(OPENSSLDIR)/include
	$(CC) $(CFLAGS) -o main main.c $(OFILES) $(LDFLAGS)
	$(CC) $(CFLAGS) -o performance performance.c $(OFILES) $(LDFLAGS)

test:
	./main

clean:
	rm -f *.o
	rm -f main performance

prettyprint:
	astyle --style=java --indent=tab --pad-header --pad-oper --align-pointer=name --align-reference=name --suffix=none *.h *.c
