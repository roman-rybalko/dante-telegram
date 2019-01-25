#!/usr/bin/perl -w
#
# maxconn.pl - open as many simulations connections as possible via SOCKS server
#

#  Copyright (c) 2011, 2012, 2013, 2015, 2016, 2017
#       Inferno Nettverk A/S, Norway.  All rights reserved.
# 
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#  1. The above copyright notice, this list of conditions and the following
#     disclaimer must appear in all copies of the software, derivative works
#     or modified versions, and any portions thereof, aswell as in all
#     supporting documentation.
#  2. All advertising materials mentioning features or use of this software
#     must display the following acknowledgement:
#       This product includes software developed by
#       Inferno Nettverk A/S, Norway.
#  3. The name of the author may not be used to endorse or promote products
#     derived from this software without specific prior written permission.
# 
#  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
#  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
#  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
#  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
#  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
#  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
#  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
#  Inferno Nettverk A/S requests users of this software to return to
# 
#   Software Distribution Coordinator  or  sdc@inet.no
#   Inferno Nettverk A/S
#   Oslo Research Park
#   Gaustadalleen 21
#   NO-0349 Oslo
#   Norway
# 
#  any improvements or extensions that they make and grant Inferno Nettverk A/S
#  the rights to redistribute these changes.

#XXX -i option not properly handled (missing in getopt etc.)

use IO::Socket::INET;
use POSIX qw(_exit);
use Getopt::Std;
use Errno;
use strict;
use Carp;

$| = 1;

my $AUTHPASS;
my $AUTHUSER;
my $IGNOREERR = 0;
my $MAXCONN = 10;
my $MAXDUR = 20; #abort test after this many seconds
my $MAXERR = 5;
my $TIMEOUT = 5;
my $VERBOSE = 0;
my $QUIET = 0; #warnings/errors only
my $METHODVAL; #method value for socks 5 method request negotiation

my $RETCODE = 0; #return code to use at exit

my $app = __FILE__;
$app =~ s/.*\/([^\/]+)$/$1/; #basename URL
my $usage = "$app: [-b addr ] [-c conncnt] [-I host:port] [-N] [-O iplist] [-pqv] [-R host:port] [-s sockshost:socksport] [-w sec]
 -b <bindaddr>            : bind to bindaddr before connecting to bound port
 -c <conncnt>             : open conncnt connections (default $MAXCONN)
 -E <maxerr>              : maximum number of connect errors
 -i                       : ignore connect/etc. errors
 -I <remhost:remport>     : connect to remote host/port and maintain connection
 -l <host:port>           : bind local port to specified host/port
 -N                       : connect to socks server without doing negotiation
 -O iplist                : set list of option28 socket options before connect
 -p                       : progress, print a dot for each connection
 -q                       : quiet, only output errors/warnings
 -R <remhost:remport>     : connect to specified host (which should timeout)
 -s <sockshost:socksport> : use SOCKS server on host:port
 -U user:pass             : username and password for SOCKS method negotation
 -v                       : enable verbose output mode
 -w <sec>                 : sleep the specified number of seconds before exit
 -W <pidfile>             : detach before sleep, after opening connections
";

#parse agruments
my $dobind = 0;
my $usesocks = 0;
my $progress = 0;
my $waitsec = 0;
my $nonegconn = 0; #connect to socks server, without doing negotiation
my $doconnect = 0; #connect to specified host/port and maintain connection
my $reqconn = 0;   #attempt to connect to specified host (should time out)
my $sockshost;
my $socksport;
my $remhost;
my $remport;
my $reqhost;
my $reqport;
my $bindaddr;
my $waitfork;
getopts('b:c:E:I:l:NO:R:pqs:U:vw:W:');

if (defined $::opt_b and defined $::opt_I) {
    die "$app: error: only one of option -b option -I can be used.\n";
}

if (defined $::opt_b) {
    $dobind = 1;
    $bindaddr = $::opt_b;
    $doconnect = 1;
}

(defined $::opt_c) and ($MAXCONN = $::opt_c);
(defined $::opt_E) and ($MAXERR = $::opt_E);
(defined $::opt_i) and ($IGNOREERR = $::opt_i);
(defined $::opt_q) and ($QUIET = $::opt_q);
(defined $::opt_v) and ($VERBOSE = $::opt_v);

#(io process)
if (defined $::opt_I) {
    die "$app: invalid -I argument: $::opt_I\n" unless $::opt_I =~ /^([^:]+):([^:]+)$/;
    ($remhost, $remport) = ($1, $2);
    $doconnect = 1;
    if ($remport !~ /^\d+$/) {
	$remport = getservbyname($remport, 'tcp');
    }
    die "$app: invalid -I port argument" unless
	defined $remport and $remport =~ /^\d+/;
}

#local end of outgoing process
my ($lhost, $lport);
if (defined $::opt_l) {
    die "$app: invalid host/port specification: $::opt_l\n" unless
	$::opt_l =~ /^([^\s:]+)$/ or $::opt_l =~ /^([^\s:]+):(\S*)$/;
    $lhost = $1;
    $lport = $2 if $2;

    if (defined $lport and $lport !~ /^\d+$/) {
	$lport = getservbyname($lport, 'tcp');
	die "$app: error: unable to resolve: $lport" unless defined $lport;
    }
}

#(negotiate process)
if (defined $::opt_N) {
    if (!defined $::opt_s) {
	die "$app: error: -N option without specified socks server (-s option).";
    }
    $nonegconn = $::opt_N;
}

#option28 data
my @OPT28IPS;
my $optdata = "";
if (defined $::opt_O) {
    @OPT28IPS = split(/,/, $::opt_O);
    for my $ip (@OPT28IPS) {
	die "$app: invalid option28 ip address: $ip\n" unless
	    $ip =~ /^\d+\.\d+\.\d+\.\d+$/;
	$optdata .= inet_aton($ip);
    }
}
my $optstr = join " ", @OPT28IPS;

#(request process)
if (defined $::opt_R) {
    die "$app: invalid -R argument: $::opt_R\n" unless
	$::opt_R =~ /^([^:]+):([^:]+)$/;
    ($reqhost, $reqport) = ($1, $2);
    $reqconn = 1;
    if ($reqport !~ /^\d+$/) {
	$reqport = getservbyname($reqport, 'tcp');
    }
    die "$app: invalid -R port argument" unless
	defined $reqport and $reqport =~ /^\d+/;
}

(defined $::opt_p) and ($progress = $::opt_p);
if (defined $::opt_s) {
    die "$app: invalid -s argument: $::opt_s\n" unless
	$::opt_s =~ /^([^:]+):([^:]+)$/;
    ($sockshost, $socksport) = ($1, $2);
    $usesocks = 1;
    if ($socksport !~ /^\d+$/) {
	$socksport = getservbyname($socksport, 'tcp');
    }
    die "$app: invalid -s port argument" unless
	defined $socksport and $socksport =~ /^\d+/;
}

if (defined $::opt_U) {
    if ($::opt_U !~ /^([^:]*):([^:]*)/) {
	die "$app: error: invalid -U username:password specification: $::opt_U";
    }
    $AUTHUSER = $1;
    $AUTHPASS = $2;
}
if (!$METHODVAL) {
    if (!defined $AUTHUSER) {
	$METHODVAL = 0;
    } else {
	$METHODVAL = 2;
    }
}

(defined $::opt_w) and ($waitsec = $::opt_w);
(defined $::opt_W) and ($waitfork = $::opt_W);

if (!$nonegconn and !$doconnect and !$reqconn) {
    die "$app: error: no operation requested, nothing to do.\n";
}

$SIG{PIPE} = sub { die "sigpipe!" };
$SIG{ALRM} = sub { die "alarm\n" }; #NB: \n required
alarm $MAXDUR;

#bind to specified host:port
my $bindpid;
$SIG{CHLD} = $SIG{INT} = $SIG{TERM} = sub {
    if (defined $bindpid) {
#	warn "$app: caught sigchld/sigint/sigterm, terminating child process\n";
	kill(2, $bindpid);
	sleep 1;
	kill(9, $bindpid);
    }
    exit 1;
};

my @c;

if ($dobind) {
    #bind socket
    my $bsock = IO::Socket::INET->new(Listen => 5,
				      LocalAddr => $bindaddr,
				      ReuseAddr => 1,
				      Proto     => 'tcp');
    die "$app: bind failure: $bindaddr: $!\n" unless defined $bsock;

    #address might change if run under socksify
    my $sockaddr = inet_ntoa($bsock->sockaddr);
    my $sockport = $bsock->sockport;
    $remhost = $sockaddr;
    $remport = $sockport;
    warn "$app: binding to $remhost:$remport ($bindaddr)\n" if $VERBOSE;

    my $pid;
    if (($pid = fork()) == -1) {
	die "$app: fork: $!\n";
    } elsif ($pid == 0) {
	#child - loop forever, accepting connections
	$SIG{INT} = $SIG{TERM} = sub {
	    my $got = $#c + 1;
	    if (!$QUIET) {
		warn "$app: terminating, $got connections accepted in total\n";
	    }
            _exit(0);
	};
	my $cnt = 0;
	for (;;) {
	    $cnt++;
	    print "." if $progress;
	    my $client = $bsock->accept();
	    if (!$client) {
		warn "$app: error: accept: $!\n";
		if ($!{EMFILE} or $!{ENFILE}) {
		    my $got = $#c + 1 ;
		    warn "$app: error: local descriptor limit error after $got connections, aborting. Please increase the number of descriptors available to $app and retry.\n";
		}
		_exit(1);
	    }
	    push @c, $client;
	    my $got = $#c + 1;
	    warn "$app: got connection ($cnt/$MAXCONN)\n" if ($got % 10) == 0;
	}
	die "$app: internal error"; #should never get here
    }
    #parent
    $bindpid = $pid;
#    warn "$app: dobind mode: forked, pid: $pid";
    $bsock->close;
}

if ($reqconn) {
    my $pid;
    if (($pid = fork()) == -1) {
	die "$app: fork: $!\n";
    } elsif ($pid == 0) {
	#run connect loop
	connloop($reqhost, $reqport, $lhost, $lport);
        _exit(0);
    }
    #parent
}

if ($nonegconn) {
    my $pid;
    if (($pid = fork()) == -1) {
	die "$app: fork: $!\n";
    } elsif ($pid == 0) {
	#give other types time to connect to socks server
	sleep 5 if $reqconn or $doconnect;
	#run connect loop
	$usesocks = 0;
	warn "$app: connecting (only) to socks server at $sockshost:$socksport\n" if $VERBOSE;
	connloop($sockshost, $socksport, $lhost, $lport);
        _exit(0);
    }
    #parent
}

if ($doconnect) {
    connloop($remhost, $remport, $lhost, $lport);
}

wait if $nonegconn;
wait if $reqconn;

#terminate any child processes
if ($bindpid) {
    $SIG{CHLD} = $SIG{INT} = $SIG{TERM} = "DEFAULT";
#    warn "$app: ending, terminating child process\n";
    kill(2, $bindpid);
    my $r;
    eval {
	local $SIG{ALRM} = sub { die "alarm\n" }; #NB: \n required

	alarm 1;
	$r = waitpid($bindpid, 0);
	alarm 0;
    };
    if ($@) {
	die "$app: error: unexpected failure: $@" if $@ ne "alarm\n";
	kill(9, $bindpid);
	wait;
    }
    if ($r == -1) {
	warn "$app: warning: wait: $!\n";
    }
}

exit $RETCODE;

######################################################################
sub connloop {
    my $remhost = shift @_;
    my $remport = shift @_;
    my $lhost = shift @_;
    my $lport = shift @_;

    my @o;
    my $attempts = 0;
    my $connfail = 0;
    while ($#o + 1 < $MAXCONN) {
	$attempts++;
	if ($attempts > $MAXCONN * 2) {
	    warn "$app: too many failures ($attempts attempts for $MAXCONN connections), aborting\n";
	    $RETCODE = 1;
	    last;
	}
	my $osock;
	warn "$app: connection open: $attempts/$MAXCONN\n" if ($attempts % 10) == 0;
	my ($connhost, $connport);
	if ($usesocks) {
	    $connhost = $sockshost;
	    $connport = $socksport;
	} else {
	    $connhost = $remhost;
	    $connport = $remport;
	}

	my $proto_tcp = 6;
	my $s = socket($osock, PF_INET, SOCK_STREAM, $proto_tcp);
	if (!defined $s) {
	    warn "$app: error: socket: $!\n";
	    if ($!{EMFILE} or $!{ENFILE}) {
		my $got = $#c + 1 ;
		warn "$app: error: local descriptor limit error after $attempts connect attempts, aborting. Please increase the number of descriptors available to $app and retry.\n";
	    }

	    last;
	}
	if ($optdata) {
	    my $OPTION28 = 28;
	    my $SOL_TCP = 6;
	    warn "$app: setting option28 data: $optstr\n" if $VERBOSE;
	    setsockopt($osock, $SOL_TCP, $OPTION28, $optdata) 
		or warn "$app: warning: setsockopt: $!\n";
	}
	my $sockname = "";
	if (defined $lhost or defined $lport) {
	    $lport = 0 if !defined $lport;
	    $lhost = "0.0.0.0" if !defined $lhost;
	    bind($osock, sockaddr_in($lport, inet_aton($lhost)))
		or die "$app: error: bind: ${lhost}.$lport $!\n";

	    my $now = localtime time;
	    my $sockname = sockname($osock);
#	    warn "$now: $app: starting connect from $sockname to server at ${connhost}.$connport\n";
	} elsif ($usesocks) {
	    #bind to get source port
	    $lport = 0;
	    $lhost = "0.0.0.0";
	    bind($osock, sockaddr_in($lport, inet_aton($lhost)))
		or die "$app: error: bind: ${lhost}.$lport $!\n";

	    my $now = localtime time;
	    my $sockname = sockname($osock);
#	    warn "$now: $app: starting connect from $sockname to server at ${connhost}.$connport\n";
	} else {
	    #XXX do not want to bind alway in case we are run under socksify
	}

	$sockname = "from $sockname " if $sockname;
	my $connstr = "";
	if ($usesocks) {
	    $connstr = "connect ${sockname}to SOCKS server at ${connhost}.$connport";
	} else {
	    $connstr = "connect ${sockname}to remote server at ${connhost}.$connport";
	}
	eval {
	    local $SIG{ALRM} = sub { die "alarm\n" }; #NB: \n required

	    alarm $TIMEOUT;
	    connect($osock, sockaddr_in($connport, inet_aton($connhost)))
		    or die "$!\n";
	    alarm 0;
	};
	if ($@) {
	    $osock->close if defined $osock;

	    if ($@ eq "alarm\n") {
		warn "$app: $connstr failed: timeout";
	    } else {
		warn "$app: $connstr failed: $@";
	    }

	    $connfail++;
	    if ($connfail > $MAXERR) {
		warn "$app: too many failures ($connfail), ending\n";
		last;
	    }
	    next;
	}

	my $now = localtime time;
	$sockname = sockname($osock);
	warn "$now: $app: connect from $sockname to server at ${connhost}.$connport complete\n" if $VERBOSE;
	if ($usesocks) {
	    warn "$now: $app: starting socks request for ${remhost}.${remport}\n" if $VERBOSE;

	    my ($res, $err);
	    eval {
		local $SIG{ALRM} = sub { die "alarm\n" }; #NB: \n required

		alarm $TIMEOUT;
		($res, $err) = socksreq($osock, $remhost, $remport);
		alarm 0;
	    };

	    if ($@) {
		die "$app: error: unexpected failure: $@" if $@ ne "alarm\n";

		$osock->close if defined $osock;
		warn "$app: SOCKS request failure: timeout\n";

		$connfail++;
		if ($connfail > $MAXERR) {
		    warn "$app: too many failures ($connfail), ending\n";
		    last;
		}
		next;
	    }

	    if (!defined $res) {
		warn "$app: SOCKS request failure: $err\n";

		$connfail++;
		if ($connfail > $MAXERR) {
		    warn "$app: too many failures ($connfail), ending\n";
		    last;
		}
		next;
	    }
	}
	#ok, add connection
	push @o, $osock;
    }

    my $opencnt = $#o + 1;
    if ($opencnt > 0 and $connfail > $MAXERR) {
	warn "$app: multiple connect failures, proxy resource limit likely reached; consult proxy log file for verification\n";
    }
    if (!$QUIET) {
	warn "$app: successfully opened $opencnt/$MAXCONN connection(s) in total\n";
    }
    if ($opencnt > 0 and $waitsec) {
	if (defined $waitfork) {
	    #detach before sleep
	    my $pid = fork;
	    die "$app: fork: $!\n" if ($pid == -1);
	    if ($pid > 0) {
		if (!open(PID, ">$waitfork")) {
		    warn "$app: error: unable to create $waitfork: $!\n";
		    kill $pid; #no pidfile, kill child
		    exit -1;
		}
		print PID "$pid\n";
		close PID;
		use POSIX qw(_exit);
		_exit(0);
	    }
	}

	warn "$app: sleeping before exit\n";
	sleep $waitsec;
    }
    for (@o) {
	$_->close or die "$app: close: $!\n";
    }
}

sub socksreq {
    my $sock = shift @_;
    my $host = shift @_;
    my $port = shift @_;

    #SOCKS5 connect request
    my ($res0, $err0) = req_rep_v5_method({ 'vn' => 5,
					    'nmethods' => 1,
					    'methods' => [$METHODVAL]},
					  1,
					  $sock);
    if (!defined $res0) {
	return (undef, "SOCKS5 method request failed (connect): $err0");
    }
    if ($res0->{'method'} != $METHODVAL) {
	return (undef, "SOCKS5 method request failed (got method: $res0->{'method'}, requested $METHODVAL)");
    }

    if ($res0->{'method'} == 2) {
	if ($VERBOSE) {
	    warn "$app: doing socks user/pass negotiation";
	}
	my $mres = socks_v5_methodneg($sock,
				      { 'ver' => 1,
					'ulen' => length($AUTHUSER),
					'uname' => $AUTHUSER,
					'plen' => length($AUTHPASS),
					'passwd' => $AUTHPASS});
	if (!defined $mres or $mres == 0) {
	    return (undef, "SOCKS5 method negotiation failed: $!" )
	}
	my ($mrep, $merr) = socks_v5_methodnegrep($sock);
	if (!defined $mrep) {
	    return (undef, "method negotiation failed (2): $merr");
	}
	if (defined $mrep and $mrep->{'status'} != 0) {
	    return (undef, "SOCKS5 method negotiation failed (got status: $mrep->{status}): $merr");
	}
    }

    my ($res, $err) = req_rep_v5({ 'vn' => 5,
				   'cd' => 1,
				   'rsv' => 0,
				   'atyp' => 1,
				   'dstip' => $host,
				   'dstport' => $port},
				 1,
				 $sock);
    if (!defined $res) {
	return(undef, "SOCKS5 connect request failed: $err");
    }

    my $v5err = v5err2txt($res->{'rep'});
    if ($res->{'rep'} == 0) {
	return ($res, "SOCKS request succeeded");
    } else {
	return (undef, "SOCKS5 connect request failed: $v5err");
    }
}

sub req_rep_v5_method {
    my $vars = shift;
    my $retsock = shift;
    my $usesock = shift;

    for my $opt (qw(vn nmethods methods)) {
        defined $vars->{$opt} or die "$app: req_rep_v5_method: $opt missing";
    }

    #VER | NMETHODS | METHODS                                                    
    my $header = "";
    $header .= pack("CC", $vars->{'vn'}, $vars->{'nmethods'});
    for my $method (@{ $vars->{'methods'} }) {
        $header .= pack("C", $method);
    }

    my $sock;
    die "$app: no socket specified" unless defined $usesock;
    $sock = $usesock;

    warn "$app: Sending request: " . bin2txt($header) . "\n" if $VERBOSE;
    syswrite($sock, $header) or die "$app: syswrite: $!";

    my ($res, $err) = parse_v5rep1($sock);
    return ($res, $err) if !defined $res;

    if (defined $retsock and defined $res) {
        $res->{'sock'} = $sock;
    } else {
        close $sock;
    }

    return $res;
}

sub socks_v5_methodneg {
    my $sock = shift;
    my $vars = shift;

    for my $opt (qw(ver ulen uname plen passwd)) {
        defined $vars->{$opt} or die "socks_v5_methodneg: $opt missing";
    }

    #VER | ULEN | UNAME | PLEN | PASSWD
    my $header = "";
    $header .= pack("CC", $vars->{'ver'}, $vars->{'ulen'});
    $header .= $vars->{'uname'};
    $header .= pack("C", $vars->{'plen'});
    $header .= $vars->{'passwd'};

    if ($VERBOSE) {
	print "Sending request: " . bin2txt($header) . "\n";
    }

    #XXX error message
    return syswrite($sock, $header);
}

sub socks_v5_methodnegrep {
    my $sock = shift;

    my ($rep, $err) = sysreadn($sock, 2);
    if (!defined $rep or length($rep) < 2) {
	warn "$app: warning: parse_v5_methodnegrep: $err" if $VERBOSE;
	return (undef, $err);
    }
    my ($ver, $status) = unpack("CC", $rep);

    my $res = { 'ver' => $ver, 'status' => $status };

    return $res;
}

sub req_rep_v5 {
    my $vars = shift;
    my $retsock = shift;
    my $usesock = shift;

    for my $opt (qw(vn cd rsv atyp dstip dstport)) {
        defined $vars->{$opt} or die "$app: req_rep_v5: $opt missing";
    }

    #VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT
    my $header = "";
    $header .= pack("CCCC", $vars->{'vn'}, $vars->{'cd'}, $vars->{'rsv'}, $vars->{'atyp'});
    if ($vars->{'dstip'} =~ /^\d+\.\d+\.\d+\.\d+$/) {
        $header .= inet_aton($vars->{'dstip'});
    } elsif ($vars->{'dstip' =~ /:/}) {
        die "$app: error: unsupported address type: ipv6";
    } elsif ($vars->{'dstip'} =~ /\w/) {
        my $len = length($vars->{'dstip'});
        die "$app: error: name too long" if $len > 255;
        $header .= pack("C", $len);
        $header .= $vars->{'dstip'};
    } else {
        die "$app: error: unable to determine address format: $vars->{dstip}";
    }

    $header .= pack("n", $vars->{'dstport'});

    my $sock;
    die "$app: error: no socket specified" unless defined $usesock;
    $sock = $usesock;

    warn "$app: Sending request: " . bin2txt($header) . "\n" if $VERBOSE;
    syswrite $sock, $header;

    my ($res, $err) = parse_v5rep2($sock);

    if (defined $retsock and defined $res) {
        $res->{'sock'} = $sock;
    } else {
        close $sock;
    }

    return ($res, $err);
}

sub parse_v5rep1 {
    my $sock = shift;

    my ($rep, $err) = sysreadn($sock, 2);
    if (!defined $rep) {
      warn "$app: warning: parse_v5rep1: $err" if $VERBOSE;
      return (undef, $err);
    }
    my ($vn, $method) = unpack("CC", $rep);

    warn "$app: Server reply: VN: $vn METHOD: $method\n" if $VERBOSE;

    my $res = { 'vn' => $vn, 'method' => $method };

    return $res;
}

sub parse_v5rep2 {
    my $sock = shift;

    my ($rep, $err) = sysreadn($sock, 4);
    if (!defined $rep) {
      warn "$app: warning: parse_v5rep2(1): $err" if $VERBOSE;
      return (undef, $err);
    }
    my ($vn, $servrep, $rsv, $atyp) = unpack("CCCC", $rep);

    my $bndaddr;
    if ($atyp == 1) {
	($rep, $err) = sysreadn($sock, 4);
	if (!defined $rep) {
	    warn "$app: warning: parse_v5rep2(2): $err" if $VERBOSE;
	    return (undef, $err);
	}
        $bndaddr = inet_ntoa($rep);
    } elsif ($atyp == 3) {
        #len in first octet
        die "$app: error: unsupported address type: $atyp";
    } elsif ($atyp == 4) {
        die "$app: error: unsupported address type: $atyp";
    } else {
	die "$app: unexpected address type $atyp";
    }

    ($rep, $err) = sysreadn($sock, 2);
    if (!defined $rep) {
      warn "$app: warning: parse_v5rep2(3): $err" if $VERBOSE;
      return (undef, $err);
    }
    my ($bndport) = unpack("n", $rep);

    warn "$app: Server reply: VN: $vn REP: $servrep RSV: $rsv ATYP: $atyp BND.ADDR: $bndaddr BND.PORT: $bndport\n" if $VERBOSE;

    my $res = { 'vn' => $vn, 'rep' => $servrep, 'rsv' => $rsv, 'atyp' => $atyp,
                'dstip' => $bndaddr, 'dstport' => $bndport };

    return $res;
}

sub bin2txt {
    my $bin = shift @_;
    my @bytes = unpack("C*", $bin);
    my $s = "";
    for (@bytes) {
        $s .= sprintf "%%%02X", $_;
    }
    return $s;
}

sub sysreadn { 
    my $sock = shift @_;
    my $len = shift @_;

    my $rep = "";
    while (length($rep) < $len) {
	my $rlen = $len - length($rep);
	my $rdat;

	my $r = sysread($sock, $rdat, $rlen);
	if (!defined $r) {
	    return (undef, "sysread: $!");
	} elsif ($r == 0) {
	    return (undef, "EOF");
	} elsif ($r < $len) {
	    return (undef, "short read");
	}
	$rep .= $rdat;
    }

    return $rep;
}

sub v5err2txt {
    my $code = shift @_;

    my @msg = ('Succeeded',
	       'General SOCKS server failure',
	       'Connection not allowed by ruleset',
	       'Network unreachable',
	       'Host unreachable',
	       'Connection refused',
	       'TTL expired',
	       'Command not supported',
	       'Address type not supported');
    return $msg[$code] if (defined $msg[$code]);
    return "Unassigned error";
}

sub sockname {
    my $sock = shift @_;

    my $sockaddr = getsockname($sock) or die "$app: getsockname: $!\n";
    my ($port0, $addr0) = sockaddr_in($sockaddr);
    die "$app: sockaddr_in failure" unless defined $addr0;
    $addr0 = inet_ntoa($addr0);
    die "$app: inet_ntoa failure" unless defined $addr0;
    return "${addr0}.${port0}";
}
