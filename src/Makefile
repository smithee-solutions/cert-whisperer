# Makefile for cert-whisperer

# Copyright 2017 Smithee Solutions LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

TROOT=opt/tester
PROGS=cert-herder cert-whisper configure-CA
SCRIPTS=openssl-TEMPLATE_1.cnf
LD=clang
CC=clang
LDFLAGS=-g
CFLAGS=-c -g -I../include -Wall -Werror


all:	${PROGS}

clean:
	rm -rf ${PROGS} core *.o ${TROOT}

build:	all
	mkdir -p ${TROOT}/bin
	cp ${PROGS} ${TROOT}/bin
	mkdir -p ${TROOT}/etc/cwCA
	cp ${SCRIPTS} ${TROOT}/etc/cwCA

cert-herder:	cert-herder.o Makefile
	${LD} -o cert-herder cert-herder.o ${LDFLAGS} -ljansson

cert-herder.o:	cert-herder.c ../include/cert-whisperer.h
	${CC} ${CFLAGS} cert-herder.c

cert-whisper:	cert-whisper.o cw-signer.o cw-utils.o Makefile
	${LD} -o cert-whisper cert-whisper.o cw-signer.o cw-utils.o ${LDFLAGS} -ljansson

cert-whisper.o:	cert-whisper.c ../include/cert-whisperer.h
	${CC} ${CFLAGS} cert-whisper.c

configure-CA:	configure-CA.o cw-utils.o Makefile
	${LD} -o configure-CA configure-CA.o cw-utils.o ${LDFLAGS} -ljansson

configure-CA.o:	configure-CA.c ../include/cert-whisperer.h
	${CC} ${CFLAGS} configure-CA.c

cw-signer.o:	cw-signer.c ../include/cert-whisperer.h
	${CC} ${CFLAGS} cw-signer.c

cw-utils.o:	cw-utils.c ../include/cert-whisperer.h
	${CC} ${CFLAGS} cw-utils.c

