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

#VERSION 1.2.7

use Net::Ping;
use LWP::UserAgent;
use LWP::ConnCache;
use HTTP::Response;
use Digest::MD5;
use threads;
use Getopt::Long;

use strict;
use warnings;

print "+ web sorrow 1.2.7 Version detection, misconfig, and enumeration tool\n";


my $i;
my $port = 0;
my $Opt;

my $ua = LWP::UserAgent->new(conn_cache => 1);
$ua->conn_cache(LWP::ConnCache->new); # use connection cacheing (faster)
$ua->agent("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.5) Gecko/20031027");


GetOptions("host=s" => \my $Host, # host ip or domain
		"Ps" => \my $Ps, # port scan
		"Eb" => \my $Eb, # error begging
		"S" => \my $S, # Standard checks
		"auth" => \my $auth, # MEH!!!!!! self explanitory
		"cmsPlugins" => \my $cmsPlugins, # cms plugins
		"I" => \my $interesting, # find interesting text in /index.whatever
		"Ws" => \my $Ws, # Web services
		"e" => \my $e, # EVERYTHINGGGGGGGG
		"proxy=s" => \my $ProxyServer, #use a proxy
		"Fd" => \my $Fd, # files and dirs
);

# usage
if(!defined $Host){
print q{
usage:
	-host [host] - Defines host to scan.
	-proxy [ip:port] - use a proxy server [not on -Ps]
	-S - Standard misconfig and other checks
	-Ps - Scans ports 1-100 with tcp probes
	-Eb - Error Begging. Sometimes a 404 page contains server info such as daemon or even the OS
	-auth - Dictionary attack to find login pages [not passwords]
	-cmsPlugins - check for cms plugins [outdated 2010]
	-I - Find interesting strings in html [very verbose]
	-Fd - look for common interesting files and dirs
	-Ws - look for Web Services on host. such as hosting porvider or blogging service
	-e - everything. run all scans

Example:
	perl Wsorrow.pl -host scanme.nmap.org -S
	perl Wsorrow.pl -host scanme.nmap.org -Eb -Ps
	perl Wsorrow.pl -host 66.11.227.35 -S -Ws -I -proxy 129.255.1.17:3128
};
exit();
}




print "+ Host: $Host\n";

if(defined $ProxyServer){
	print "+ Proxy: $ProxyServer\n";
}
print "+ Start Time: " . localtime() . "\n";
print "-" x 70 . "\n";


if($Host =~ /http(s|):\/\//i){ #check host input
	print "- No \"http:/\/\" please! just domain name or IP ADDR\n";
	exit();
}


#triger scans


if(defined $ProxyServer){
	&proxy(); # always make sure to put this first, lest we send un-proxied packets
}

my $resAnalIndex = $ua->get("http://$Host/"); # looks a bit out of place but needs to be before everything

if(defined $S){
	&Standard();
}

if(defined $Ps){
	print "+ running port scanner\n";
	&PortScan();
}

if(defined $Eb){
	print "+ runnning  Error begging scanner\n";
	&ErrorBegging();
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
	&Standard();

	print "+ running port scanner\n";
	&PortScan();
	
	print "+ runnning  Error begging scanner\n";
	&ErrorBegging();
	
	print "+ running auth aka login page finder\n";
	&auth();
	
	print "+ running Interesting text scanner\n";
	&interesting();
	
	print "+ running Web Service scanner\n";
	&webServices();
	
	print "+ running Interesting files and dirs scanner\n";
	&FilesAndDirsGoodies();
	
	print "+ running cms plugin detection scanner\n";
	&cmsPlugins();

}

print "\n+ done :'(  -  Finshed on " . localtime;






#----------------------------------------------------------------------------------------------------------------
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
	
	unless($checkURL =~ /\//){
		$checkURL = "/" . $checkURL;
	}
	
	#False Positive checking
	my @PosibleErrorStrings = ('404 error','error 404','error 400','not found','cannot be found','could not find','can’t find','bad request','server error','temporarily unavailable','not exist','unable to open','check your spelling');
	foreach my $errorCheck (@PosibleErrorStrings){
		if($CheckResp =~ /$errorCheck/i){
			print "+ Item \"$checkURL\" Contained text: \"$errorCheck\" MAYBE a False Positive!\n";
		}
	}
	
	
	# check page size
	my $IndexLength = length($resAnalIndex->as_string()); # get byte length of page
	if(length($IndexLength) > 100) { chop $IndexLength;chop $IndexLength; } # make byte length aproximate
	
	my $respLength = length($CheckResp);
	if(length($respLength) > 100) { chop $respLength;chop $respLength; }
	
	if($IndexLength eq $respLength){
		print "+ the length of \"$checkURL\" is about the same as / This is MAYBE a redirect\n";
	}
	
	if(length($CheckResp) < 100){
		print "+ \"$checkURL\" is very small. this MAYBE a False Positive!";
	}
	
	
	# check headers
	my @analheadersChop = split("\n\n", $CheckResp);
	my @analHeaders = split("\n", $analheadersChop[0]); # tehe i know...
	
	foreach my $analHString (@analHeaders){ # method used in sub Standard is not used because of custom msgs and there's not more then 2 headers per msg so why bother
	
		#the page is empty?
		if($analHString =~ /Content-Length: (0|1)$/i){
			print "+ Banner Graber - \"$checkURL\" contained header: \"$analHString\" MAYBE a False Positive or is empty!\n";
		}
		
		#auth page checking
		if($analHString =~ /www-authenticate:/i){
			print "+ Banner Graber - \"$checkURL\" contained header: \"$analHString\" Hmmmm\n";
		}
		
		#a hash?
		if($analHString =~ /Content-MD5:/i){
			print "+ Banner Graber - \"$checkURL\" contains header: \"$analHString\" Hmmmm\n";
		}
		
		#redircted me?
		if($analHString =~ /refresh:/i){
			print "+ Banner Graber - \"$checkURL\" - looks like it redirects. header: \"$analHString\"\n";
		}
		
		if($analHString =~ /http\/1.1 30(1|2|7)/i){
			print "+ Banner Graber - \"$checkURL\" - looks like it redirects. header: \"$analHString\"\n";
		}
		
		if($analHString =~ /location:/i){
			my @checkLocation = split(/:/,$analHString);
			my $lactionEnd = $checkLocation[1];
			unless($lactionEnd =~ /$checkURL/i){
				print "+ Banner Graber - The header: \"$analHString\" does not match the requested page: $checkURL MAYBE a redirect?\n";
			}
		}
		
	}
	



}

sub genErrorString{
	my $errorStringGGG = "";
	for($i = 0;$i < 20;$i++){
		$errorStringGGG .= chr((int(rand(93)) + 33)); # random 20 bytes to invoke 404 sometimes 400
	}
	
	$errorStringGGG =~ s/(#|&|\?)//g; #strip anchors and q stings
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
		chomp $MSG;
		
		# send req and validate
		my $checkMsgDir = $ua->get("http://$Host" . $JustDir);
		if($checkMsgDir->is_success){
			print "+ $scanMSG: \"$JustDir\"  -  $MSG\n";
			&analyzeResponse($checkMsgDir->as_string() ,$JustDir);
		}
}

sub nonSyntDatabaseScan{ # for DBs without the dir;msg format
	my $DataFromDBNonSynt = shift;
	my $scanMSGNonSynt = shift;
	chomp $DataFromDBNonSynt;
		
		# send req and check if it's valid
		my $checkDir = $ua->get("http://$Host/" . $DataFromDBNonSynt);
		if($checkDir->is_success){
			print "+ $scanMSGNonSynt: \"/$DataFromDBNonSynt\"\n";
			&analyzeResponse($checkDir->as_string() ,$DataFromDBNonSynt);
		}
}

sub matchScan{
	my $checkMatchFromDB = shift;
	my $checkMatch = shift;
	my $matchScanMSG = shift;
	chomp $checkMatchFromDB;
	
	
		my @matchScanLineFromDB = split(';',$checkMatchFromDB);
		my $msJustString = $matchScanLineFromDB[0]; #String to find
		my $msMSG = $matchScanLineFromDB[1]; #this is the message printed if it isn't an error

		if($checkMatch =~ /$msJustString/){
			print "+ $matchScanMSG: $msMSG\n";
		}
		
}


#---------------------------------------------------------------------------------------------------------------
# scanning subs


sub Standard{ #some standard stuff
		
		# banner grabing
		my @checkHeaders = ('x-powered-by:','server:','x-meta-generator:','x-meta-framework:','x-meta-originator:','x-aspnet-version:','www-authenticate:','x-xss.*:', 'refresh:', 'location:',);

		my $resP = $ua->get("http://$Host/");
		my $headers = $resP->as_string();
		
		my @headersChop = split("\n\n", $headers);
		my @headers = split("\n", $headersChop[0]);
		
		foreach my $HString (@headers){
			foreach my $checkSingleHeader (@checkHeaders){
				if($HString =~ /$checkSingleHeader/i){
					print "+ Banner Graber - " . $HString . "\n";
				}
			}
		}
		
		
		#robots.txt
		my $roboTXT = $ua->get("http://$Host/robots.txt");
		unless($roboTXT->is_error){
			&analyzeResponse($roboTXT->as_string() ,"/robots.txt");
			
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
					print "+ Directory indexing found in \"$dir\" - AND it looks like an Apache server!\n";
					&analyzeResponse($IndexFind->as_string() ,$dir);
				}

				# Tomcat
				if($IndexFind->content =~ /<title>Directory Listing For \/.*<\/title>/i and $IndexFind->content =~ /<body><h1>Directory Listing For \/.*<\/h1>/i){
					print "+ Directory indexing found in \"$dir\" - AND it looks like an Apache Tomcat server!\n";
					&analyzeResponse($IndexFind->as_string() ,$dir);
				}

				# iis
				if($IndexFind->content =~ /<body><H1>$Host - $dir/i){
					print "+ Directory indexing found in \"$dir\" - AND it looks like an IIS server!\n";
					&analyzeResponse($IndexFind->as_string() ,$dir);
				}
				
			}
		}
		
		# laguage checks
		my $LangReq = $ua->get("http://$Host/");
		my @langSpaceSplit = split(/ / ,$LangReq->decoded_content);
		
		my $langString = 'lang=';
		my @langGate;
		
		foreach my $lineIDK (@langSpaceSplit){
			if($lineIDK =~ /$langString('|").*?('|")/i){
				while($lineIDK =~ "\t"){ #make pretty
					$lineIDK =~ s/\t//sg;
				}
				while($lineIDK =~ /(<|>)/i){ #prevent html from sliping in
					chop $lineIDK;
				}
				
				
				unless($lineIDK =~ /lang=('|")('|")/){ # empty?
					print "+ page Laguage found: $lineIDK\n";
				}
			}
		}
		
		
		
		
		# Some servers just give you a 200 with every req. lets see
		my @webExtentions = ('.php','.html','.htm','.aspx','.asp','.jsp','.cgi');
		foreach my $Extention (@webExtentions){
			my $testErrorString = &genErrorString();
			my $check200 = $ua->get("http://$Host/$testErrorString" . $Extention);
			
			if($check200->is_success){
				print "+ /$testErrorString" . $Extention . " responded with code: " . $check200->code . " the server might just responde with this code even when the dir, file, or Extention: $Extention doesn't exist! any results from this server may be void\n";
				&analyzeResponse($check200->as_string() ,"$testErrorString" . $Extention);
			}
		}
		
		#does the site have a mobile page?
		my $MobileUA = LWP::UserAgent->new;
		$MobileUA->agent('Mozilla/5.0 (iPhone; U; CPU like Mac OS X; en) AppleWebKit/420+ (KHTML, like Gecko) Version/3.0');
		my $mobilePage = $MobileUA->get("http://$Host/");
		my $regularPage = $ua->get("http://$Host/");
		
		unless($mobilePage->content() eq $regularPage->content()){
			print "+ index page reqested with an Iphone UserAgent is diferent then with a regular UserAgent. This Host may have a mobile site\n";
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

		my $getErrorString = &genErrorString();
		my $_404responseGet = $ua->get("http://$Host/$getErrorString");
		&checkError($_404responseGet);
		
		my $postErrorString = &genErrorString();
		my $_404responsePost = $ua->post("http://$Host/$postErrorString");
		&checkError($_404responsePost);


		sub checkError{
			my $_404response = shift;
		
			if($_404response->is_error) {
				print "+ Error Begging " . $_404response->code . " - ";
				my $siteHTML = $_404response->decoded_content;
				
				
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
						print "\n+ Found 404 page but not printing. To Big :(\n";
					}
				} else {
					print $siteNaked . "\n\n";
				}
			}
		}
		
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




sub cmsPlugins{ # Plugin databases provided by: Chris Sullo from cirt.net
	print "+ CMS Plugins takes awhile....\n";
	my @cmsPluginDBlist = ('DB/drupal_plugins.db','DB/joomla_plugins.db','DB/wp_plugins.db');
	
	foreach my $cmsPluginDB (@cmsPluginDBlist){
		print "+ Testing Plugins with Database: $cmsPluginDB\n";
			
		open(cmsPluginDBFile, "+< $cmsPluginDB");
		my @parsecmsPluginDB = <cmsPluginDBFile>;

		foreach my $JustDir (@parsecmsPluginDB){
			&nonSyntDatabaseScan($JustDir,"CMS Plugin Found");
		}
		close(cmsPluginDBFile);

	}


}




sub FilesAndDirsGoodies{ # databases provided by: raft team
	print "+ interesting Files And Dirs takes awhile....\n";
	my @FilesAndDirsDBlist = ('DB/raft-small-directories.db','DB/raft-small-files.db',);
	
	foreach my $FilesAndDirsDB (@FilesAndDirsDBlist){
			print "+ Testing Files And Dirs with Database: $FilesAndDirsDB\n";
			
			open(FilesAndDirsDBFile, "+< $FilesAndDirsDB");
			my @parseFilesAndDirsDB = <FilesAndDirsDBFile>;
			
			foreach my $JustDir (@parseFilesAndDirsDB){
				&nonSyntDatabaseScan($JustDir,"interesting File or Dir Found");
			}
		close(FilesAndDirsDBFile);

	}


}




sub webServices{ # as of v 1.2.7 it's acually worth the time typing "-Ws" to use it! HORAYYY
	open(webServicesDB, "+< DB/web-services.db");
	my @parsewebServicesdb = <webServicesDB>;
	
	my $webServicesTestPage = $ua->get("http://$Host/");
	
	my @webServicesStringMsg;
	foreach my $lineIDK (@parsewebServicesdb){
		push(@webServicesStringMsg, $lineIDK);
	}
	

		
	foreach my $ServiceString (@webServicesStringMsg){
		&matchScan($ServiceString,$webServicesTestPage->content,"Web service Found");
	}


	close(webServicesDB);
	
	&faviconMD5(); # i'll just make a new sub
	&cms();
}




sub faviconMD5{ # thanks to OWASP
	
	my $favicon = $ua->get("http://$Host/favicon.ico");
	
	if($favicon->is_success){
		&analyzeResponse($favicon->as_string() ,"/favicon.ico");
	
		#make checksum
		my $MD5 = Digest::MD5->new;
		$MD5->add($favicon->content);
		my $checksum = $MD5->hexdigest;
		

		open(faviconMD5DB, "+< DB/favicon.db");
		my @faviconMD5db = <faviconMD5DB>;
		
		
		my @faviconMD5StringMsg; # split DB by line
		foreach my $lineIDK (@faviconMD5db){
			push(@faviconMD5StringMsg, $lineIDK);
		}
		
		foreach my $faviconMD5String (@faviconMD5StringMsg){
			&matchScan($faviconMD5String,$checksum,"Web service Found (favicon.ico)");
		}

		close(faviconMD5DB);
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




sub interesting{ # look for DBs, dirs, login pages, and emails and such
	my @interestingStings = ('https:\/\/','/cgi-bin','/wp-content/plugins/','password','passwd','admin','database','payment','bank','account','twitter.com','facebook.com','login','@.*?(com|org|net|tv|uk|au|edu|mil|gov)','<!--#');
	my $mineIndex = $ua->get("http://$Host/");
	
	foreach my $checkInterestingSting (@interestingStings){
		my @IndexData = split(/</,$mineIndex->decoded_content);
		
		foreach my $splitIndex (@IndexData){
			if($splitIndex =~ /$checkInterestingSting/i){
				while($splitIndex =~ /(\n|\t|  )/){
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