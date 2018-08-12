# make file for cert-whisperer

all:
	(cd src; make all )

clean:
	(cd src; make clean )
	(cd test; make clean )

build:	all
	(cd src; make build )

test:	build
	(cd test; make test )

