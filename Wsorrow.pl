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

#VERSION 1.2.3

use Net::Ping;
use LWP::UserAgent;
use HTTP::Response;
use threads;
use Getopt::Long;
use strict;

print "+ Web sorrow 1.2.3 Version detection and misconfig scanning tool\n";


my $i;
my $port = 0;
my $Opt;
my $ua = LWP::UserAgent->new;
$ua->agent("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.5) Gecko/20031027");



GetOptions("host=s" => \my $Host, # host ip or domain
		"Ps" => \my $Ps, # port scan
		"Eb" => \my $Eb, # error begging
		"Nc" => \my $Nc, # No Core
		"cms" => \my $cms, # Looks for version info with default cms files
		"auth" => \my $auth, # MEH!!!!!! self explanitory
		"cmsPlugins" => \my $cmsPlugins, # cms plugins
		"I" => \my $interesting, # find interesting text in /index.whatever
		"e" => \my $e, # EVERYTHINGGGGGGGG
		"proxy=s" => \my $ProxyServer,
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
	-auth - Dictionary attack to find login pages [not passwords]
	-cmsPlugins - check for cms plugins [outdated 2010]
	-I    - Find interesting strings in html [very verbose]
	-e    - everything. run all scans
	-proxy - use a proxy server. ip:port
	
Example:
	perl Wsorrow.pl -host scanme.nmap.org
	perl Wsorrow.pl -host scanme.nmap.org -Eb -Ps
	perl Wsorrow.pl -host 66.11.227.35 -Nc -cms -I -proxy 129.255.1.17:3128
};
exit();
}



print "-" x 70 . "\n";
print "+ Host: $Host\n";
if(defined $ProxyServer){
	print "+ Proxy: $ProxyServer\n";
}

if(defined $e){
	print "+ Enabled: EVERYTHING!\n";
}

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
if(defined $interesting){
	print "+ Enabled: mine interesting text\n";
}
print "+ Start Time: " . localtime() . "\n";
print "-" x 70 . "\n";


if($Host =~ "http:"){ #check host input
	print "- No http:// please! just domain name or IP ADDR\n";
	exit();
}

#run scans

if(defined $ProxyServer){
	&proxy(); # always make sure to put this first, lest we send un-proxied packets
}


if(!defined $Nc){
	&core();
}

if(defined $Ps){
	print "+ running port scanner\n";
	&PortScan();
}

if(defined $Eb){
	print "+ runnning  Error begging scanner\n";
	&ErrorBegging();
}

if(defined $cms){
	print "+ running cms version detection scanner\n";
	&cms();
}

if(defined $auth){
	print "+ running auth aka login page finder\n";
	&auth();
}

if(defined $cmsPlugins){
	print "+ running cms plugin detection scanner\n"
	&cmsPlugins();
}

if(defined $interesting){
	print "+ running Interesting text scanner\n";
	&interesting();
}


if(defined $e){

	print "+ running port scanner\n";
	&PortScan();
	
	print "+ runnning  Error begging scanner\n";
	&ErrorBegging();
	
	print "+ running cms version detection scanner\n";
	&cms();
	
	print "+ running auth aka login page finder\n";
	&auth();
	
	print "+ running Interesting text scanner\n";
	&interesting();
	
	print "+ running cms plugin detection scanner\n"
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
	my ($CheckReq,$checkURI) = @_;
	my @PosibleErrorStrings = ('error 404','error 400','not found','could not find','Bad Request','server error');
	foreach my $errorCheck (@PosibleErrorStrings){
		if($CheckReq =~ /$errorCheck/i){
			print "- Page $checkURI Contained text: $errorCheck may be a False Positive!\n";
		}
		if($CheckReq =~ /www-authenticate:/i){ # this didn't have much of a use when parsing /index.whatever
				print "+ Banner Graber - $checkURI contained banner: www-authenticate Hmmmm\n";
		}
	}
	
}

sub genErrorString{
	my $errorStringGGG = "";
	for($i = 0;$i < 20;$i++){
		$errorStringGGG .= chr((int(rand(93)) + 33)); # random 20 byte to invoke 404 sometimes 400
	}
	return $errorStringGGG;
}

sub proxy{ # simple!!! i loves it
	$ua->proxy('http',"http://$ProxyServer");
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
			
			if($HString =~ /www-authenticate:/i){
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
		}
		
		
		
		#lilith 6.0A rework of sub indexable with a cupple additions.
		
		my @CommonDIRs = ('/images','/imgs','/img','/icons','/home','/wp-content','/pictures','/main','/css','/style','/styles','/docs','/pics','/_','/thumbnails','/thumbs','/scripts','/files');
		&checkOpenDirListing(@CommonDIRs);
		
		sub checkOpenDirListing{
			my (@DIRlist) = @_;
			foreach my $dir (@DIRlist){

				my $IndexFind = $ua->get("http://$Host" . $dir);
					
				# Apache
				if($IndexFind->content =~ /<H1>Index of \/.*<\/H1>/i){
					# extra checking (<a.*>last modified</a>, ...)
					print "+ Directory indexing found in $dir - AND it looks like an Apache server!\n";
					&checkFalsePositives($IndexFind->decoded_content ,$dir);
				}

				# Tomcat
				if($IndexFind->content =~ /<title>Directory Listing For \/.*<\/title>/i and $IndexFind->content =~ /<body><h1>Directory Listing For \/.*<\/h1>/i){
					print "+ Directory indexing found in $dir - AND it looks like an Apache Tomcat server!\n";
					&checkFalsePositives($IndexFind->decoded_content ,$dir);
				}

				# iis
				if($IndexFind->content =~ /<body><H1>$Host - $dir/i){
					print "+ Directory indexing found in $dir - AND it looks like an IIS server!\n";
					&checkFalsePositives($IndexFind->decoded_content ,$dir);
				}
				
			}
		}
		
		# laguage checks
		my $LangReq = $ua->get("http://$Host/");
		my @langSpaceSplit = split(/ / ,$LangReq->decoded_content);
		
		my $langString = 'lang=';
		
		foreach my $lineIDK (@langSpaceSplit){
			if($lineIDK =~ /$langString('|").*?('|")/i){
				while($lineIDK =~ "\t"){ #make pretty
					$lineIDK =~ s/\t//sg;
				}
				while($lineIDK =~ /(<|>)/i){ #prevent html from sliping in
					chop $lineIDK;
				}
				
				print "+ page Laguage found: $lineIDK\n";
			}
		}
		
		
		# Some servers just give you a 200 with every req. lets see
		for($i = 0;$i < 5;$i++){
			my $errorString = &genErrorString();
			my $check200 = $ua->get("http://$Host/$errorString");
			
			if($check200->is_success){
				print "+ /$errorString responded with code: " . $check200->code . " the server might just responde with this code even when the dir or file don't exist!\n";
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

		my $errorString = &genErrorString();
		my $response = $ua->get("http://$Host/$errorString");
		sleep(1);
		&checkError();
		
		
		$errorString = &genErrorString();
		$response = $ua->post("http://$Host/$errorString");
		sleep(1);
		&checkError();


		sub checkError{
			if($response->is_error) {
				print "+ Error Begging " . $response->code . " - ";
				my $siteHTML = $response->decoded_content;
				
				
				### strip html tags and make pretty [very close to perfectly]
				$siteHTML =~ s/<script.*?<\/script>//sgi;
				$siteHTML =~ s/<style.*?<\/style>//sgi;
				$siteHTML =~ s/<(?!--)[^'">]*"[^"]*"/</gi;
				$siteHTML =~ s/<(?!--)[^'">]*'[^']*'/</gi;
				$siteHTML =~ s/<(?!--)[^">]*>//gi;
				$siteHTML =~ s/<!--.*?-->//gi;
				$siteHTML =~ s/<.*?>//gi;
				$siteHTML =~ s/\n/ /g;
				while($siteHTML =~ "  "){
					$siteHTML =~ s/  / /g;
				}
				while($siteHTML =~ "\t"){
					$siteHTML =~ s/\t//sg;
				}
				
				
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
	
	my @cmsDirMsg;
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
	
	my @authDirMsg;
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
		if($authCheckMsgDir->is_success or $authCheckMsgDir->code == 401 or $authCheckMsgDir->code == 403){
			print "+ Login Page Found: $JustDir  -  $MSG";
			&checkFalsePositives($authCheckMsgDir->decoded_content ,$JustDir);
		}
	}


	close(authDB);
}




sub cmsPlugins{ # Plugin databases provided by: Chris Sullo from cirt.net
	print "+ CMS Plugins takes awhile....\n";
	my @cmsPluginDBlist = ('DB/joomla_plugins.db','DB/drupal_plugins.db','DB/wp_plugins.db');
	
	foreach my $cmsPluginDB (@cmsPluginDBlist){
			print "+ Testing Plugins with Database: $cmsPluginDB\n";
			
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




sub interesting{ # look for DBs, dirs, login pages, and emails and such
	my @interestingStings = ('https:','password','passwd','admin','database','payment','bank','account','twitter.com','facebook.com','login','@.*?(com|org|net|tv|uk|mil|gov)');
	my $mineIndex = $ua->get("http://$Host/");
	
	foreach my $checkInterestingSting (@interestingStings){
		my @IndexData = split(/</,$mineIndex->decoded_content); # im not yet certian slpliting by ('|") is the best method
		
		foreach my $splitIndex (@IndexData){
			if($splitIndex =~ /$checkInterestingSting/i){
				while($splitIndex =~ "\n" or $splitIndex =~ "\t" or $splitIndex =~ "  "){
					$splitIndex =~ s/\n/ /g;
					$splitIndex=~ s/\t//g;
					$splitIndex=~ s/  / /g;
				}
				# the split chops of < so i just stick it in there to make it look pretty
				print "+ interesting text found in: <$splitIndex\n";
			}
			
		}

	}
}