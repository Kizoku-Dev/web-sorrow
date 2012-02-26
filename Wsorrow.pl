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

#VERSION 1.2.4

use Net::Ping;
use LWP::UserAgent;
use HTTP::Response;
use threads;
use Getopt::Long;
use strict;
#use warnings; #I turn this on just before release to look for bugs 

print "+ Web sorrow 1.2.4 Version detection and misconfig scanning tool\n";


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
		"Ws" => \my $Ws,
		"e" => \my $e, # EVERYTHINGGGGGGGG
		"proxy=s" => \my $ProxyServer, #use a proxy
		"Fd" => \my $Fd,
);

# usage
if(!defined $Host){
print q{
usage:
	-host [host] - Defines host to scan.
	-proxy [ip:port] - use a proxy server [not on -Ps].
	-Nc - Disables standard misconfig checks
	-Ps - Scans ports 1-100 with tcp probes
	-Eb - Error Begging. Sometimes a 404 page contains server info such as daemon or even the OS
	-cms - Looks for version info with default cms files
	-auth - Dictionary attack to find login pages [not passwords]
	-cmsPlugins - check for cms plugins [outdated 2010]
	-I - Find interesting strings in html [very verbose]
	-Fd - look for common interesting files and dirs
	-Ws - look for Web Services on host. such as hosting porvider or blogging service
	-e - everything. run all scans

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
if(defined $Fd){
	print "+ Enabled: interesting files and dirs\n";
}
if(defined $Ws){
	print "+ Enabled: Web Service testing\n";
}
print "+ Start Time: " . localtime() . "\n";
print "-" x 70 . "\n";


if($Host =~ "http:\/\/"){ #check host input
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
	print "+ running cms plugin detection scanner\n";
	&cmsPlugins();
}

if(defined $interesting){
	print "+ running Interesting text scanner\n";
	&interesting();
}

if(defined $Fd){
	print "+ running Interesting files and dirs scanner\n";
	&FilesAndDirsGoodies();
}

if(defined $Ws){
	print "+ running Web Service scanner\n";
	&webServices();
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
	
	print "+ running cms plugin detection scanner\n";
	&cmsPlugins();
	
	print "+ running Interesting files and dirs scanner\n";
	&FilesAndDirsGoodies();
	
	print "+ running Web Service scanner\n";
	&webServices();

}

print "\n+ done :'(  -  Finshed on " . localtime;

#----------------------------------------------------------------------------------------------------------------




# non scanning subs for clean code and speed 'n stuff

sub PromtUser{ # Yes or No?
	my $PromtMSG = shift; # i find the shift is much sexyer then then @_
	
	print $PromtMSG;
	$Opt = <stdin>;
	return $Opt;
}

sub analyzeResponse{ # heres were all the smart is...
	my $CheckResp = shift;
	my $checkURL = shift;
	
	#False Positive checking
	my @PosibleErrorStrings = ('error 404','error 400','not found','could not find','bad request','server error');
	foreach my $errorCheck (@PosibleErrorStrings){
		if($CheckResp =~ /$errorCheck/i){
			return "- Page $checkURL Contained text: \"$errorCheck\" MAYBE a False Positive!\n";
		}
	}
	
	$CheckResp =~ s/\r//g;
	my @analHeaders = split("\n", $CheckResp); # tehe i know...
		
	foreach my $analHString (@analHeaders){
	
		#auth page checking
		if($analHString =~ /www-authenticate:/i){
			return "+ Banner Graber - $checkURL contained header: $analHString Hmmmm\n";
		}
		
		#the page is empty?
		if($analHString =~ /Content-Length: (0|1)/i){
			return "+ Banner Graber - $checkURL contained header: $analHString which is weird Hmmmm\n";
		}
		
		#a hash?
		if($analHString =~ /Content-MD5:/i){
			return "+ Banner Graber - $checkURL contains header: $analHString Hmmmm\n";
		}
		
		#redircted me?
		if($analHString =~ /refresh:/i){
			print "+ Banner Graber - $checkURL - looks like it redirects. header: $analHString\n";
		}
		
		if($analHString =~ /location:/i){
			my @checkLocation = split(/:/,$analHString);
			my $lactionEnd = $checkLocation[1];
			if($lactionEnd =! /$checkURL/i){
				print "+ Banner Graber - The header: $analHString does not match the requested page: $checkURL MAYBE a redirect?\n";
			}
		}
		
		if($analHString =~ /http\/1.1 30(1|2|7)/i){
			print "+ Banner Graber - $checkURL - looks like it redirects. header: $analHString\n";
		}
		
	}
}

sub genErrorString{
	my $errorStringGGG = "";
	for($i = 0;$i < 20;$i++){
		$errorStringGGG .= chr((int(rand(93)) + 33)); # random 20 bytes to invoke 404 sometimes 400
	}
	return $errorStringGGG;
}

sub proxy{ # simple!!! i loves it
	$ua->proxy('http',"http://$ProxyServer");
	
	if(defined $Ps){
		my $warnPortscan = &PromtUser("! WARNING: Proxy Settings do not work when using the -Ps do you want to exit? (y/N) ");
		if($warnPortscan =~ /n/i){
			exit();
		}
	}
}

sub dataBaseScan{ # use a database for scanning.
	my $DataFromDB = shift;
	my $scanMSG = shift;
	
	
		# take data from database and seperate dir from msg
		my @LineFromDB = split(';',$DataFromDB);
		my $JustDir = $LineFromDB[0]; #Dir or file to req
		my $MSG = $LineFromDB[1]; #this is the message printed if the url req isn't an error
		
		# send req and validate
		my $checkMsgDir = $ua->get("http://$Host" . $JustDir);
		unless($checkMsgDir->is_error){
			print "+ $scanMSG: $JustDir  -  $MSG";
			print &analyzeResponse($checkMsgDir->as_string() ,$JustDir);
		}
}




#---------------------------------------------------------------------------------------------------------------



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
			
			if($HString =~ /x-meta-originator:/i){
				print "+ Banner Graber - " . $HString . "\n";
			}
			
			if($HString =~ /x-aspnet-version:/i){
				print "+ Banner Graber - " . $HString . "\n";
			} 
			
			if($HString =~ /www-authenticate:/i){
				print "+ Banner Graber - " . $HString . "\n";
			}
			
			if($HString =~ /x-xss.*:/i){
				print "+ Banner Graber - " . $HString . "\n";
			}
			
			if($HString =~ /refresh:/i){
				print "+ Banner Graber - " . $HString . " - looks like it redirects to something\n";
			}
			
			if($HString =~ /content-location:/i){
				print "+ Banner Graber - " . $HString . " - looks like it redirects to something\n";
			}
		}
		
		
		#robots.txt
		my $roboTXT = $ua->get("http://$Host/robots.txt");
		unless($roboTXT->is_error){
			print &analyzeResponse($roboTXT->as_string() ,"/robots.txt");
			
			my $Opt = &PromtUser("+ robots.txt found! This could be interesting!\n+ would you like me to display it? (y/n) ? ");

			if($Opt =~ /y/i){
				print "+ robots.txt Contents: \n";
				print $roboTXT->decoded_content . "\n";
			}
		}
		
		
		
		#lilith 6.0A rework of sub indexable with a cupple additions.
		
		my @CommonDIRs = ('/images','/imgs','/img','/icons','/home','/pictures','/main','/css','/style','/styles','/docs','/pics','/_','/thumbnails','/thumbs','/scripts','/files');
		&checkOpenDirListing(@CommonDIRs);
		
		sub checkOpenDirListing{
			my (@DIRlist) = @_;
			foreach my $dir (@DIRlist){

				my $IndexFind = $ua->get("http://$Host" . $dir);
					
				# Apache
				if($IndexFind->content =~ /<H1>Index of \/.*<\/H1>/i){
					# extra checking (<a.*>last modified</a>, ...)
					print "+ Directory indexing found in $dir - AND it looks like an Apache server!\n";
					print &analyzeResponse($IndexFind->as_string() ,$dir);
				}

				# Tomcat
				if($IndexFind->content =~ /<title>Directory Listing For \/.*<\/title>/i and $IndexFind->content =~ /<body><h1>Directory Listing For \/.*<\/h1>/i){
					print "+ Directory indexing found in $dir - AND it looks like an Apache Tomcat server!\n";
					print &analyzeResponse($IndexFind->as_string() ,$dir);
				}

				# iis
				if($IndexFind->content =~ /<body><H1>$Host - $dir/i){
					print "+ Directory indexing found in $dir - AND it looks like an IIS server!\n";
					print &analyzeResponse($IndexFind->as_string() ,$dir);
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
			my ($pingHost, $portBase) = @_;

			for my $port ($portBase .. $portBase + 19) {
				my $ping = Net::Ping->new("tcp");
				$ping->port_number($port);

				print "+ OPEN tcp port $port\n" if $ping->ping($pingHost);
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
				$siteHTML =~ s/<(?!--)[^'">]*"[^"]*"/</sgi;
				$siteHTML =~ s/<(?!--)[^'">]*'[^']*'/</sgi;
				$siteHTML =~ s/<(?!--)[^">]*>//sgi;
				$siteHTML =~ s/<!--.*?-->//sgi;
				$siteHTML =~ s/<.*?>//sgi;
				$siteHTML =~ s/\n/ /sg;
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
		&dataBaseScan($cmsDirAndMsg,'cms version info Found'); #this func can only be called when the DB uses the /dir;msg format
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
		&dataBaseScan($authDirAndMsg,'Login Page Found');
	}


	close(authDB);
}




sub webServices{ # needs a bit of refining and expansion
	open(webServicesDB, "+< DB/web-services.db");
	my @parsewebServicesdb = <webServicesDB>;
	
	my $webServicesTestPage = $ua->get("http://$Host/");
	
	my @webServicesStringMsg;
	foreach my $lineIDK (@parsewebServicesdb){
		push(@webServicesStringMsg, $lineIDK);
	}
	

		
	foreach my $ServiceString (@webServicesStringMsg){
		my @webServicesLineFromDB = split(';',$ServiceString);
		my $JustString = $webServicesLineFromDB[0]; #String to find in page
		my $MSG = $webServicesLineFromDB[1]; #this is the message printed if the url req isn't an error

		if($webServicesTestPage->decoded_content =~ /$JustString/i){
			print "+ Web Service Found: $MSG";
		}
		
	}


	close(webServicesDB);
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
					print &analyzeResponse($cmsPluginDir->as_string() ,$JustDir);
				}
			}
		close(cmsPluginDBFile);

	}


}




sub FilesAndDirsGoodies{ # databases provided by: raft team
	print "+ interesting Files And Dirs takes awhile....\n";
	my @FilesAndDirsDBlist = ('DB/raft-small-directories.db','DB/raft-small-files.db');
	
	foreach my $FilesAndDirsDB (@FilesAndDirsDBlist){
			print "+ Testing Files And Dirs with Database: $FilesAndDirsDB\n";
			
			open(FilesAndDirsDBFile, "+< $FilesAndDirsDB");
			my @parseFilesAndDirsDB = <FilesAndDirsDBFile>;
			
			foreach my $JustDir (@parseFilesAndDirsDB){
				chomp $JustDir;
				# send req and check if it's valid
				my $FilesAndDirsDir = $ua->get("http://$Host/" . $JustDir);
				if($FilesAndDirsDir->is_success){
					print "+ interesting File or Dir Found: /$JustDir\n";
					print &analyzeResponse($FilesAndDirsDir->as_string() ,$JustDir);
				}
			}
		close(FilesAndDirsDBFile);

	}


}




sub interesting{ # look for DBs, dirs, login pages, and emails and such
	my @interestingStings = ('https:','/wp-content/plugins/','password','passwd','admin','database','payment','bank','account','twitter.com','facebook.com','login','@.*?(com|org|net|tv|uk|mil|gov)','<!--#');
	my $mineIndex = $ua->get("http://$Host/");
	
	foreach my $checkInterestingSting (@interestingStings){
		my @IndexData = split(/</,$mineIndex->decoded_content);
		
		foreach my $splitIndex (@IndexData){
			if($splitIndex =~ /$checkInterestingSting/i){
				while($splitIndex =~ "\n" or $splitIndex =~ "\t" or $splitIndex =~ "  "){
					$splitIndex =~ s/\n/ /g;
					$splitIndex=~ s/\t//g;
					$splitIndex=~ s/  / /g;
				}
				# the split chops off < so i just stick it in there to make it look pretty
				print "+ interesting text found in: <$splitIndex\n";
			}
			
		}

	}
}