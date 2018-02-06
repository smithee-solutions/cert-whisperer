#!/usr/bin/perl

# CA.pl from openssl 1.0.2d modified for SOCA

my $openssl;
$openssl = "/tester/current/bin/openssl";

$SSLEAY_CONFIG=$ENV{"SSLEAY_CONFIG"};

$cert_day_param=$ENV{"CERT_DAYS"};
$DAYS="-days $cert_day_param";
$ca_day_param=$ENV{"CA_DAYS"};
$CADAYS="-days $ca_day_param";
$REQ="$openssl req $SSLEAY_CONFIG";
$CA="$openssl ca $SSLEAY_CONFIG";
$VERIFY="$openssl verify";
$X509="$openssl x509";
$PKCS12="$openssl pkcs12";

$CATOP=$ENV{"CA_DIR"};
$CAKEY="cakey.pem";
$CAREQ="careq.pem";
$CACERT="cacert.pem";
$SUBJECT = $ENV{"DUT_DN"};

$DIRMODE = 0777;

$RET = 0;

foreach (@ARGV) {
	if ( /^(-\?|-h|-help)$/ ) {
	    print STDERR "usage: CA -newcert|-newreq|-newreq-nodes|-newca|-sign|-verify\n";
	    exit 0;
	} elsif (/^-newcert$/) {
	    # create a certificate
	    system ("$REQ -new -x509 -keyout newkey.pem -out newcert.pem $DAYS");
	    $RET=$?;
	    print "Certificate is in newcert.pem, private key is in newkey.pem\n"
	} elsif (/^-newreq$/) {
	    # create a certificate request
	    system ("$REQ -new -keyout newkey.pem -out newreq.pem $DAYS");
	    $RET=$?;
	    print "Request is in newreq.pem, private key is in newkey.pem\n";
	} elsif (/^-newreq-nodes-param$/) {
	    # create a certificate request
	    system ("$REQ -new -nodes ${SUBJECT} -keyout newkey.pem -out newreq.pem $DAYS");
	    $RET=$?;
	    print "Request is in newreq.pem, private key is in newkey.pem\n";
	} elsif (/^-newca-nodes$/) {
	    $NEW="1";
	    if ( "$NEW" || ! -f "${CATOP}/serial" ) {
		# create the directory hierarchy
		mkdir $CATOP, $DIRMODE;
		mkdir "${CATOP}/certs", $DIRMODE;
		mkdir "${CATOP}/crl", $DIRMODE ;
		mkdir "${CATOP}/newcerts", $DIRMODE;
		mkdir "${CATOP}/private", $DIRMODE;
		open OUT, ">${CATOP}/index.txt";
		close OUT;
		open OUT, ">${CATOP}/crlnumber";
		print OUT "01\n";
		close OUT;
	    }
	    if ( ! -f "${CATOP}/private/$CAKEY" ) {
		    print "Making CA certificate ...\n";
		    system ("$REQ -new -nodes ${SUBJECT} -keyout ${CATOP}/private/$CAKEY -out ${CATOP}/$CAREQ");
		    system ("$CA -create_serial " .
			"-out ${CATOP}/$CACERT $CADAYS -batch " . 
			"-keyfile ${CATOP}/private/$CAKEY -selfsign " .
			"-extensions v3_ca " .
			"-infiles ${CATOP}/$CAREQ ");
		    $RET=$?;
	    }
	} elsif (/^-newca$/) {
		# if explicitly asked for or it doesn't exist then setup the
		# directory structure that Eric likes to manage things 
	    $NEW="1";
	    if ( "$NEW" || ! -f "${CATOP}/serial" ) {
		# create the directory hierarchy
		mkdir $CATOP, $DIRMODE;
		mkdir "${CATOP}/certs", $DIRMODE;
		mkdir "${CATOP}/crl", $DIRMODE ;
		mkdir "${CATOP}/newcerts", $DIRMODE;
		mkdir "${CATOP}/private", $DIRMODE;
		open OUT, ">${CATOP}/index.txt";
		close OUT;
		open OUT, ">${CATOP}/crlnumber";
		print OUT "01\n";
		close OUT;
	    }
	    if ( ! -f "${CATOP}/private/$CAKEY" ) {
		print "CA certificate filename (or enter to create)\n";
		$FILE = <STDIN>;

		chop $FILE;

		# ask user for existing CA certificate
		if ($FILE) {
		    cp_pem($FILE,"${CATOP}/private/$CAKEY", "PRIVATE");
		    cp_pem($FILE,"${CATOP}/$CACERT", "CERTIFICATE");
		    $RET=$?;
		} else {
		    print "Making CA certificate ...\n";
		    system ("$REQ -new -keyout " .
			"${CATOP}/private/$CAKEY -out ${CATOP}/$CAREQ");
		    system ("$CA -create_serial " .
			"-out ${CATOP}/$CACERT $CADAYS -batch " . 
			"-keyfile ${CATOP}/private/$CAKEY -selfsign " .
			"-extensions v3_ca " .
			"-infiles ${CATOP}/$CAREQ ");
		    $RET=$?;
		}
	    }
	} elsif (/^-pkcs12$/) {
	    my $cname = $ARGV[1];
	    $cname = "My Certificate" unless defined $cname;
	    system ("$PKCS12 -in newcert.pem -inkey newkey.pem " .
			"-certfile ${CATOP}/$CACERT -out newcert.p12 " .
			"-export -name \"$cname\"");
	    $RET=$?;
	    print "PKCS #12 file is in newcert.p12\n";
	    exit $RET;
	} elsif (/^-xsign$/) {
	    system ("$CA -policy policy_anything -infiles newreq.pem");
	    $RET=$?;
	} elsif (/^(-sign|-signreq)$/) {
	    system ("$CA -batch -policy policy_anything -out newcert.pem " .
							"-infiles newreq.pem");
	    $RET=$?;
	    print "Signed certificate is in newcert.pem\n";
	} elsif (/^(-signCA)$/) {
	    system ("$CA -policy policy_anything -out newcert.pem " .
					"-extensions v3_ca -infiles newreq.pem");
	    $RET=$?;
	    print "Signed CA certificate is in newcert.pem\n";
	} elsif (/^-signcert$/) {
	    system ("$X509 -x509toreq -in newreq.pem -signkey newreq.pem " .
								"-out tmp.pem");
	    system ("$CA -policy policy_anything -out newcert.pem " .
							"-infiles tmp.pem");
	    $RET = $?;
	    print "Signed certificate is in newcert.pem\n";
	} elsif (/^-verify$/) {
	    if (shift) {
		foreach $j (@ARGV) {
		    system ("$VERIFY -CAfile $CATOP/$CACERT $j");
		    $RET=$? if ($? != 0);
		}
		exit $RET;
	    } else {
		    system ("$VERIFY -CAfile $CATOP/$CACERT newcert.pem");
		    $RET=$?;
	    	    exit 0;
	    }
	} else {
	    print STDERR "Unknown arg $_\n";
	    print STDERR "usage: CA -newcert|-newreq|-newreq-nodes|-newca|-sign|-verify\n";
	    exit 1;
	}
}

exit $RET;

sub cp_pem {
my ($infile, $outfile, $bound) = @_;
open IN, $infile;
open OUT, ">$outfile";
my $flag = 0;
while (<IN>) {
	$flag = 1 if (/^-----BEGIN.*$bound/) ;
	print OUT $_ if ($flag);
	if (/^-----END.*$bound/) {
		close IN;
		close OUT;
		return;
	}
}
}

