#!/usr/bin/perl 

# Copyright 2012 Dakota Simonds
# A small portion of this software is from Lilith 6.0A and is Sited.
# sub checkOpenDirListing (modified) Copyright (c) 2003-2005 Michael Hendrickx

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

#VERSION 1.1

use Net::Ping;
use LWP::UserAgent;
use HTTP::Response;
use threads;
use Getopt::Long;


print "+ Web sorrow 1.2.1 Version detection and misconfig scanning tool\n";


my $port = 0;
my $ua = LWP::UserAgent->new;
$ua->agent("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.5) Gecko/20031027");



GetOptions("host=s"   => \my $Host, # host ip or domain
		"Ps" => \my $Ps, # port scan
		"Eb" => \my $Eb, # error begging
		"Nc" => \my $Nc, # No Core
		"cms" => \my $cms, # Looks for version info with default cms files
		"auth" => \my $auth, # MEH!!!!!!
		"cmsPlugins" => \my $cmsPlugins,
);

# usage
if(!defined $Host){
print q{
usage:
	-host - Defines host to scan.
	-Nc   - Disables standard misconfig checks
	-Ps   - Scans ports 1-100 with tcp probes
	-Eb   - Error Begging. Sometimes a 404 page contains server info such as daemon or even the OS
	-cms  - Looks for version info with default cms files
	-auth - Dictionary attack to find login pages
	-cmsPlugins - check for cms plugins [outdated 2010]
	
Example:
	perl Wsorrow.pl -host scanme.nmap.org
	perl Wsorrow.pl -host scanme.nmap.org -Eb -Ps
	perl Wsorrow.pl -host 66.11.227.35 -Nc -cms
};
exit();
}



print "-" x 70 . "\n";
print "+ Host: $Host\n";
if(defined $Ps){
	print "+ Enabled: Port Scan\n";
}
if(defined $Eb){
	print "+ Enabled: Error Begging\n";
}
if(defined $Nc){
	print "- Disabled: Web sorrow core\n";
}
if(defined $cms){
	print "+ Enabled: cms testing\n";
}
if(defined $auth){
	print "+ Enabled: Auth Dict. attack\n";
}
if(defined $cmsPlugins){
	print "+ Enabled: cms plugins testing\n";
}
print "+ Start Time: " . localtime() . "\n";
print "-" x 70 . "\n";


if($Host =~ "http:"){ #check host input
	print "- No http:// please! just domain name or IP ADDR\n";
	exit();
}

#run scans
if(!defined $Nc){
	&core();
}

if(defined $Ps){
	&PortScan();
}

if(defined $Eb){
	&ErrorBegging();
}

if(defined $cms){
	&cms();
}

if(defined $auth){
	&auth();
}
if(defined $cmsPlugins){
	&cmsPlugins();
}


print "\n+ done :'(  -  Finshed on " . localtime;

#----------------------------------------------------------------------------------------------------------------




# non scanning subs for clean code and speed 'n stuff

sub PromtUser{ # Yes or No?
	my ($PromtMSG) = @_;
	
	print $PromtMSG;
	$Opt = <stdin>;
	return $Opt;
}

sub checkFalsePositives{ # is it an error? i don't know if this works yet. no syntax error but not sure yet
	my ($checkReq,$checkURI) = @_;
	my @PosibleErrorStrings = ('error 404','error 400','not found','could not find','Bad Request');
	foreach my $errorCheck (@PosibleErrorStrings){
		if($CheckReq =~ /$errorCheck/i){
			print "- Page $checkURI Contained text: $errorCheck may be a False Positive!\n";
		}
	}
	
}





sub core{ #some standard stuff
		
		# banner grabing
		my $resP = $ua->get("http://$Host/");
		my $headers = $resP->as_string();
		$headers =~ s/\r//g;
		my @headers = split("\n", $headers);
		
		foreach my $HString (@headers){
			if($HString =~ /server:/i){
				print "+ Banner Graber - " . $HString . "\n";
			}
			
			if($HString =~ /x-powered-by:/i){
				print "+ Banner Graber - " . $HString . "\n";
			}
			
			if($HString =~ /x-meta-generator:/i){
				print "+ Banner Graber - " . $HString . "\n";
			}
			
			if($HString =~ /x-aspnet-version:/i){
				print "+ Banner Graber - " . $HString . "\n";
			}
			
		}
		
		
		#robots.txt
		my $roboTXT = $ua->get("http://$Host/robots.txt");
		unless($roboTXT->is_error){
			&checkFalsePositives($roboTXT->decoded_content ,"/robots.txt");
			
			my $Opt = &PromtUser("+ robots.txt found! This could be interesting!\n+ would you like me to display it? (y/n) ? ");

			if($Opt =~ /y/i){
				print "+ robots.txt Contents: \n";
				print $roboTXT->decoded_content . "\n";
			}
				
				# may use this in future
				
				
				#my @CleanRobotDirs;
				#my @DirtyRobot = split(/\n/, $roboTXT->decoded_content);
				#my $c = 0;
				
				# parse robots.txt for directories
				#foreach my $DIRcheck (@DirtyRobot){
				#	if($DIRcheck =~ /disallow:/i){
				#		$DIRcheck =~ s/disallow://ig;
				#		$DIRcheck =~ s/ //ig;
				#		$DIRcheck =~ s/\n//ig;
				#		
				#		push(@CleanRobotDirs,$DIRcheck);
				#		
				#	} elsif ($DIRcheck =~ /allow:/i){
				#		$DIRcheck =~ s/allow://ig;
				#		$DIRcheck =~ s/ //ig;
				#		$DIRcheck =~ s/\n//ig;
				#		push(@CleanRobotDirs,$DIRcheck);
				#		
				#	}

				#}

				#my $Opt = &PromtUser("+ Would you like to check robots.txt for ? (y/n) ? ");
				#if($Opt =~ /y/i){
	
				#}
		}
		
		
		
		#lilith 6.0A rework of sub indexable with a cupple additions.
		
		my @CommonDIRs = ('/images','/imgs','/img','/icons','/home','/wp-content','/pictures','/main','/css','/style','/styles','/docs','/pics','/_','/thumbnails','/thumbs','/scripts');
		&checkOpenDirListing(@CommonDIRs);
		

		
		sub checkOpenDirListing{
			my (@DIRlist) = @_;
			foreach my $dir (@DIRlist){

				my $IndexFind = $ua->get("http://$Host" . $dir);
					
				# Apache
				if($IndexFind->content =~ /<H1>Index of \/.*<\/H1>/){
					# extra checking (<a.*>last modified</a>, ...)
					print "+ Directory indexing found in $dir - AND it looks like an Apache server!\n";
					&checkFalsePositives($IndexFind->decoded_content ,$dir);
				}

				# Tomcat
				if($IndexFind->content =~ /<title>Directory Listing For \/.*<\/title>/ and $IndexFind->content =~ /<body><h1>Directory Listing For \/.*<\/h1>/){
					print "+ Directory indexing found in $dir - AND it looks like an Apache Tomcat server!\n";
					&checkFalsePositives($IndexFind->decoded_content ,$dir);
				}

				# iis
				if($IndexFind->content =~ /<body><H1>$Host - $dir/){
					print "+ Directory indexing found in $dir - AND it looks like an IIS server!\n";
					&checkFalsePositives($IndexFind->decoded_content ,$dir);
				}
				
			}
		}
		
}






sub PortScan{
		# props TheGrandFather perlmonks.org for threading
		# pings a plenty
		

			my @threads = map {
				threads->new(sub {doPing($Host, $_ * 20)})
			} 0 .. 4;

			for my $thread (@threads) {
				$thread->join();
			}

			
			
		sub doPing {
			my ($Host, $portBase) = @_;

			for my $port ($portBase .. $portBase + 19) {
				my $ping = Net::Ping->new("tcp");
				$ping->port_number($port);

				print "+ OPEN tcp port $port\n" if $ping->ping($Host);
			}
		}


}





# I don't know if this method has be used in other tools or has even been discovered before but I think it should allways be fixed 
sub ErrorBegging{
		
		my $errorString = "";
		for($i = 0;$i < 20;$i++){
			$errorString .= chr((int(rand(93)) + 33)); # random 20 byte to invoke 404 sometimes 400
		}


		my $response = $ua->get("http://$Host/$errorString");
		sleep(1);
		&checkError();
		
		
		my $errorString = "";
		for($i = 0;$i < 20;$i++){
			$errorString .= chr((int(rand(93)) + 33)); # random 20 byte to invoke 404 sometimes 400
		}
		
		$response = $ua->post("http://$Host/$errorString");
		sleep(1);
		&checkError();


		sub checkError{
			if($response->is_error) {
				print "+ Error Begging " . $response->code . " - ";
				my $siteHTML = $response->decoded_content;
				
				
				### strip html tags and prettyify [almost perfectly]
				$siteHTML =~ s/<(?!--)[^'">]*"[^"]*"/</gi;
				$siteHTML =~ s/<(?!--)[^'">]*'[^']*'/</gi;
				$siteHTML =~ s/<(?!--)[^">]*>//gi;
				$siteHTML =~ s/<!--.*?-->//gi;
				$siteHTML =~ s/<.*?>//gi;
				$siteHTML =~ s/\n/ /g;
				$siteHTML =~ s/  / /g;
				
				my $siteNaked = $siteHTML;
				if(length($siteNaked) > 1000){
					my $Opt = &PromtUser("! the Error page was found but its a bit big\n! do you still want to see it (y/n) ? ");
					if($Opt =~ /y/i){
						print $siteNaked . "\n\n";
					} else {
						print "\n+ Found 404 page put not printing. To Big :(\n";
					}
				} else {
					print $siteNaked . "\n\n";
				}
			}
		}
		
}




sub cms{
	open(cmsDB, "+< DB/CMS.db");
	my @parseCMSdb = <cmsDB>;
	
	foreach my $lineIDK (@parseCMSdb){
		push(@cmsDirMsg, $lineIDK);
	}
	
	foreach my $cmsDirAndMsg (@cmsDirMsg){
	
		# seperate dir from msg
		my @cmsdir = split(';',$cmsDirAndMsg);
		my $JustDir = $cmsdir[0];
		my $MSG = $cmsdir[1];
		
		# send req and check if it's valid
		my $checkMsgDir = $ua->get("http://$Host" . $JustDir);
		unless($checkMsgDir->is_error){
			print "+ cms default: $JustDir  -  $MSG";
			&checkFalsePositives($checkMsgDir->decoded_content ,$JustDir);
		}
	}


	close(cmsDB);
}




sub auth{ # this DB is pretty good but not complete
	open(authDB, "+< DB/login.db");
	my @parseAUTHdb = <authDB>;
	
	foreach my $lineIDK (@parseAUTHdb){
		push(@authDirMsg, $lineIDK);
	}
	
	foreach my $authDirAndMsg (@authDirMsg){
	
		# seperate dir from msg
		my @authdir = split(';',$authDirAndMsg);
		my $JustDir = $authdir[0];
		my $MSG = $authdir[1];
		
		# send req and check if it's valid
		my $authCheckMsgDir = $ua->get("http://$Host" . $JustDir);
		if($authCheckMsgDir->is_success){
			print "+ Login Page Found: $JustDir  -  $MSG";
			&checkFalsePositives($authCheckMsgDir->decoded_content ,$JustDir);
		}
	}


	close(authDB);
}



sub cmsPlugins{ # Plugin databases provided by: Chris Sullo from cirt.net
	print "+ CMS Plugins takes awhile....\n";
	@cmsPluginDBlist = ('DB/drupal_plugins.db','DB/joomla_plugins.db','DB/wp_plugins.db');
	
	foreach $cmsPluginDB (@cmsPluginDBlist){
		
			open(cmsPluginDBFile, "+< $cmsPluginDB");
			my @parsecmsPluginDB = <cmsPluginDBFile>;
		
			foreach my $JustDir (@parsecmsPluginDB){
				chomp $JustDir;
				# send req and check if it's valid
				my $cmsPluginDir = $ua->get("http://$Host/" . $JustDir);
				if($cmsPluginDir->is_success){
					print "+ CMS Plugin Found: $JustDir in DataBase $cmsPluginDB\n";
					&checkFalsePositives($cmsPluginDir->decoded_content ,$JustDir);
				}
			}
		

	}


}
