package Penguin;
$VERSION = "1.0";

=head1 NAME

Penguin - high level interface for mobile network code agents

=head1 SYNOPSIS

    use Penguin;
    use PGP; # required
    use Safe; # not required, but truly advisable

    PGP::set_secretword("Penguins fulfil my emotional needs");
    Penguin::set_portnumber(5003); # set the Penguin socket port number
    Penguin::start_listening; # create a socket to listen on 
    $numseconds = 10;
    ($signing_authority, $code) = Penguin::getcodeifthere($numseconds);
    $opmask = Penguin::getopmask($signing_authority);
    [...now use Safe to eval $code under $opmask...]
    [ future: use Penguin::execute($signing_authority, $opmask, $code); ]

    [...meanwhile, in a file very far away...]

    $code = "print 'hello\n';";
    $result = Penguin::sendcode($code, "whatever.company.com", 5003);

=head1 DESCRIPTION

This is a set of high level routines which send and receive perl
code through a 'trusted' channel.  The sending routines use PGP.pm to
'digitally sign' the code.  The receiving routines verify the signature
and then assign the code a certain set of rights depending on who the
sender is (using the fine Safe module created by Malcolm Beattie, not
included and the fine PGP module created by me, available through me).

=head1 NOTES

=head2 This is Not Finished Software

This is a very early release.  The fairly big set of missing and excluded
features includes: a superior mechanism (including, perhaps, programs)
for taking care of your opmaskfile and assigning remote parties rights;
using something native that's not PGP for the signing and verification
procedures (PGP is not designed for what this code does); a function
that sets up a large associative array which details the code's rights
and its operating environment for import and sharing with the protected
compartment; a function which permits two pieces of code executing in
separate protected compartments to share namespace; addition of a native
rlimit xs module to permit limitedpgpsafetkperl; synchronous sendcode();
and so on.

=head2 What You Need

You need an opmaskfile.  An opmaskfile is a file consisting of lines
of the form

PGPUSERNAME MASK

where PGPUSERNAME is something that is of the (PGP-standard) form

    Joe X Penguin <penguin@penguins.are.cool.com>

and MASK is of the Safe-module-defined form

00001111010101010101...

where each 0 or 1 stands for a bit in an operator mask.  If you don't
at this point have any idea what I'm talking about, you might want to
wait for the next release, which may make more sense.

Place the fully qualified filename of your opmaskfile in your
OPMASKFILE environment variable.

=head2 Bugs, Problems, Etc.

Too many to list.  Consult the README.Penguin for more information.

=head1 Contact

I'm fsg\@coriolan.amicus.com.  I love getting e-mail.  Especially if
it extends or subsumes huge chunks of my code.

=cut

use Safe 'MAXO'; # we only use this much of Safe, for handling opmasks.
use Carp;
use Socket;

# error variables
$Penguin::E_SIGN_FAILED = -1;
$Penguin::E_SOCKET_UNAVAILABLE = -2;
$Penguin::E_CANNOT_CONNECT = -3;
$Penguin::E_CANNOT_ACCEPT = -4;
$Penguin::E_CANNOT_BIND = -5;
$Penguin::E_CANNOT_LISTEN = -6;

&Penguin::bootstrap;

sub bootstrap {
    # see end of function for global variable initializations

    $Penguin::opmaskfile = $ENV{'OPMASKFILE'} ||
                           "$ENV{'HOME'}/.penguin/opmaskfile";

    $Penguin::sockaddr = 'S n a4 x8';     # Cringe.  _how_ long until IPng?
    $Penguin::port = $Penguin::port || 5059;
    $Penguin::rin = 0; # used by select() in agent-reading code
}

sub sendcode { 
    my ($codetosend) = shift;
    my ($targetmachine) = shift || 'localhost';
    my $encryptedcode = &PGP::sign($codetosend) || 
                                     return $E_SIGN_FAILED;
    my $proto = ((getprotobyname("tcp"))[2]);
    my $theiraddress = ((gethostbyname($targetmachine))[4]);
    my $theirsocket = pack($Penguin::sockaddr, AF_INET, $Penguin::port,
                           $theiraddress);

    if (! socket(S, AF_INET, SOCK_STREAM, $proto)) {
        return $E_SOCKET_UNAVAILABLE;
    }
    connect(S, $theirsocket) || return $E_CANNOT_CONNECT;
    select(S); $| = 1; select(STDOUT);

    print S $encryptedcode;
    1;
}

sub start_listening {
    # opens up a socket to listen for incoming code.
    # bootstrap has to be called first.
    # calling this function twice would be bad.
    
    my $proto=((getprotobyname("tcp"))[2]);
    my $thisend = pack($Penguin::sockaddr, AF_INET, $Penguin::port,
                       "\0\0\0\0");

    socket(AGENTSOCKET, AF_INET, SOCK_STREAM, $proto) || 
              return $E_SOCKET_UNAVAILABLE;

    bind(AGENTSOCKET, $thisend) || return $E_CANNOT_BIND;
    listen(AGENTSOCKET, 5) || return $E_CANNOT_LISTEN;
    $Penguin::rin = &fhbits(AGENTSOCKET);
    1;
}

sub getcodeifthere {
    my $delay = shift; # delay fed to select(), so is in [fractional] secs
    my $numfound;
    my $theiraddr;
    my $signedcode;
    my $savedslash = $/;

    $numfound = select($rin, undef, undef, $delay);
    
    if ($numfound > 0) {
        $theiraddr = accept(NEWAGENTSOCKET, AGENTSOCKET) || 
            return $E_CANNOT_ACCEPT;
        select(NEWAGENTSOCKET); $| = 1; select(STDOUT);
        undef $/;
        $signedcode = <NEWAGENTSOCKET>;
        $/ = $savedslash;
        return (&PGP::unsign($signedcode));
    }
    return undef;
}

sub getopmask {
    my $signing_authority = shift;
    my $opmaskfilelines = 0;
    my $opmask;
    my $defaultopmask;

    if(! -f $opmaskfile) {
        croak <<"ENDOFCROAK";
Penguin can't find an opmaskfile for you (normally a file
you keep the fully qualified name of in your OPMASKFILE
environment variable).  Penguin will now fail to guess at
what your default should be.  Please consult the documentation
for this program to determine how to set up an opmaskfile.
ENDOFCROAK
    }

    # we survived
    open(OPMASKFILE, "<$opmaskfile") || croak <<"ENDOFCROAK";
Penguin couldn't open your opmaskfile for reading.  It thinks it's
$opmaskfile.  You'll need to rectify the situation before Penguin
will work.
ENDOFCROAK
    $opmask = "not found";
    $defaultopmask = 0;
    while($line = <OPMASKFILE>) {
        if ($line =~ /${signing_authority} (.*)/) {
            $opmask = $1;
        }
        if ($line =~ /default (.*)/) {
            $defaultopmask = $1;
        }
    }
    close(OPMASKFILE);
    if ($opmask eq "not found") {
        $opmask = $defaultopmask;
    }

    # extend opmask to length of perl-compiled operator mask
    $opmask .= "0" x (Safe::MAXO() - length($opmask)); # thanks malcolm

    $opmask =~ tr/01/\0\1/; # binarize mask

    $opmask;
}

sub fhbits { # thanks larry, randal! camel book, p178:
    my @handles = @_;
    my $bits = "";
    for (@handles) {
        vec($bits, fileno($_), 1) = 1;
    }
    $bits;
}

1;
__END__;
