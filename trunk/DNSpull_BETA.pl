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

print "Web-Sorrow (Extra Tool) DNSpull v1";
print "tell me if it works for you or not @flyinpoptartcat or email\n";
	
use Net::DNS::Packet;
use Getopt::Long;

use warnings;
use strict;


my $Host = "none";
GetOptions("host=s" => \$Host);

# usage
if($Host eq "none"){
	print "Usage: perl DNSpull.pl -host example.com\n\t-host  -  domain name\n";
	exit();
}

print "+ PTR MX TXT A AAAA KX IN CNAME records:\n";

my $packet = Net::DNS::Packet->new($Host, "PTR", "MX", "TXT", "A", "AAAA", "KX", "IN", "CNAME");

print $packet->string;