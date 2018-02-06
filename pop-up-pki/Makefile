# makefile for pop-up-pki

SCRIPTS=\
  bin-src/101-create-root bin-src/102-create-sub-ca \
  bin-src/201-create-first-user \
  bin-src/202-create-users-02_thru_02 bin-src/CA.pl bin-src/setup_Pop-up-PKI \
  bin-src/PopUpPKI-params bin-src/make-hierarchy
ETC_FILES=\
  etc-src/Pop-up-PKI/template-A-CPS.txt \
  etc-src/Pop-up-PKI/template-A-openssl.cnf \
  etc-src/Pop-up-PKI/template-A-usr_cert.cnf etc-src/Pop-up-PKI/template-sub-ca.cnf \
  etc-src/Pop-up-PKI/template-device.cnf \
  etc-src/sample_local_parameters

all:	${SCRIPTS}

clean:
	rm -rvf tester

build:	all
	mkdir -p tester/current/bin
	mkdir -p tester/current/etc/Pop-up-PKI
	cp ${SCRIPTS} tester/current/bin
	cp ${ETC_FILES} tester/current/etc/Pop-up-PKI
	mkdir -p tester/current/run
	cp etc-src/sample_local_parameters tester/current/run

