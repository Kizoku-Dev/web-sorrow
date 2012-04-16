#!/usr/bin/perl
# Copyright 2012 Dakota Simonds
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

use Net::Ping;
use IO::Socket::INET;
use Getopt::Long;

use warnings;
use strict;

my $Host = "none";
GetOptions("host=s" => \$Host);

print "+ Web-Sorrow (extra tool) Simple Host Discovery v1\n";

# usage
if($Host eq "none"){
	print "Usage: perl hdt.pl -host example.com\n\t-host  -  domain or ip ADDR\n";
	exit();
}

my $Stat = "Host is DOWN";

my @ports = (7, 23, 25, 53, 54, 80, 443, 3128, 6669, 8008, 8080); # common ports

#full connect

foreach my $port (@ports) {
	
	my $SockTest = IO::Socket::INET->new(
		PeerAddr => $Host,
		PeerPort => $port,
		Proto => 'tcp'
	) or next;
	
	print "+ OPEN $port/tcp\n" and $Stat = "Host Is UP"; 
	close($SockTest);
}


# pings a plenty
my @Methods = ('tcp','icmp','udp');

foreach my $Meth (@Methods){
	foreach my $port (@ports) {
		my $ping = Net::Ping->new($Meth, 1, 50);
		$ping->port_number($port);

		print "+ OPEN $port/$Meth (ping)\n" and $Stat = "Host Is UP" if $ping->ping($Host);

	}
}

print "+ $Stat\n+ Scan finished :'(";