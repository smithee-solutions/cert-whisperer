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
PROGS=configure-CA
SCRIPTS=openssl-TEMPLATE_1.cnf
LD=clang
CC=clang
LDFLAGS=-g
CFLAGS=-c -g -Wall -Werror


all:	${PROGS}

clean:
	rm -rf ${PROGS} core *.o ${TROOT}

build:	all
	mkdir -p ${TROOT}/bin
	cp ${PROGS} ${TROOT}/bin
	mkdir -p ${TROOT}/etc/cwCA
	cp ${SCRIPTS} ${TROOT}/etc/cwCA

configure-CA:	configure-CA.o Makefile
	${LD} -o configure-CA configure-CA.o ${LDFLAGS} -ljansson

configure-CA.o:	configure-CA.c
	${CC} ${CFLAGS} configure-CA.c

