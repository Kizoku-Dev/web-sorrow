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

#VERSION 1.3.1

use LWP::UserAgent;
use LWP::ConnCache;
use HTTP::Request;
use HTTP::Response;
use Digest::MD5;
use Getopt::Long;
use encoding "utf-8";

use strict;
use warnings;


		print "\n+ Web Sorrow 1.3.1 Version detection, misconfig, and enumeration tool\n";


		my $i;
		my $Opt;
		my $Host = "none";

		my $ua = LWP::UserAgent->new(conn_cache => 1);
		$ua->conn_cache(LWP::ConnCache->new); # use connection cacheing (faster)

		$ua->agent("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.5) Gecko/20031027");


		GetOptions("host=s" => \$Host, # host ip or domain
			"S" => \my $S, # Standard checks
			"auth" => \my $auth, # MEH!!!!!! self explanitory
			"Cp=s" => \my $cmsPlugins, # cms plugins
			"I" => \my $interesting, # find interesting text
			"Ws" => \my $Ws, # Web services
			"e" => \my $e, # EVERYTHINGGGGGGGG
			"proxy=s" => \my $ProxyServer, #use a proxy
			"Fd" => \my $Fd, # files and dirs
			"Fp" => \my $Fp, # fingerprint web server
			"ninja" => \my $nin,
		);

		# usage
		if($Host eq "none"){
			&usage();
			exit();
		}


		print "+ Host: $Host\n";

		if(defined $ProxyServer){
			print "+ Proxy: $ProxyServer\n";
		}
		print "+ Start Time: " . localtime() . "\n";
		print "-" x 70 . "\n";


		if($Host =~ /http(s|):\/\//i){ #check host input
			$Host =~ s/http(s|):\/\///gi;
		}


		#triger scans


		if(defined $ProxyServer){
			&proxy(); # always make sure to put this first, lest we send un-proxied packets
		}

		&checkHostAvailibilty() unless defined $nin; # skip if --ninja for more stealth
		my $resAnalIndex = $ua->get("http://$Host/");
		
		if(defined $S){ &Standard(); }
		if(defined $nin){ &Ninja(); }
		if(defined $auth){ &auth(); }
		if(defined $cmsPlugins){ &cmsPlugins(); }
		if(defined $Fp){ &FingerPrint(); }
		if(defined $Ws){ &webServices(); }
		if(defined $Fd){ &FilesAndDirsGoodies(); }
		if(defined $e){ &runAll(); }
		
		
		
		sub runAll{
			&Standard();
			&FingerPrint();
			&auth();
			&webServices();
			&cmsPlugins();
			&FilesAndDirsGoodies();
		}




		print "-" x 70 . "\n";
		print "+ done :'(  -  Finshed on " . localtime;






#----------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------




# non scanning subs for clean code and speed 'n stuff

sub usage{

print q{
Usage: perl Wsorrow.pl [HOST OPTIONS] [SCAN(s)]

HOST OPTIONS:
    -host [host]     -- Defines host to use.
    -proxy [ip:port] -- use a proxy server
	
	
SCANS:
    -S    --  Standard misconfig and other checks
    -auth --  Dictionary attack to find login pages (not passwords)
    -Cp [dp | jm | wp | all] -- scan for cms plugins.
            dp = drupal
            jm = joomla
            wp = wordpress 
    -Fd   --  look for common interesting files and dirs
    -Fp   --  Fingerprint http server based on behavior
    -Ws   --  scan for Web Services on host such as: hosting porvider, 
              blogging service, favicon fingerprinting, and cms version info
    -e    --  everything. run all scans
	
	
OTHER:
    -I      --  Find interesting strings in responses
    -ninja  --  A light weight and undetectable scan that uses bits and peices 
                from other scans (it is not recomended to use with any other scans 
                if you want to be stealthy)

EXAMPLES:
    perl Wsorrow.pl -host scanme.nmap.org -S
    perl Wsorrow.pl -host scanme.nmap.org -Cp dp,jm
    perl Wsorrow.pl -host 66.11.227.35 -proxy 129.255.1.17:3128 -S -Ws -I 
};

}

sub checkHostAvailibilty{
	my $CheckHost1 = $ua->get("http://$Host/");
	my $CheckHost2 = $ua->get("http://$Host");
	
	if($CheckHost2->is_error and $CheckHost1->is_error){
		print "Host: $Host maybe offline or unavailble!\n";
		&PromtUser('Do you wish to continue anyway (y/n) ? ');
		if($Opt =~ /n/i){
			print "You should try hdt.pl for more conclusive host discovery\nExiting. Good Bye!\n";
			exit();
		}
	}
}

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
		$checkURL = "/" . $checkURL; # makes for good output
	}
	
	#False Positive checking
	my @ErrorStringsFound;
	
	my @PosibleErrorStrings = (
								'404 error',
								'404 page',
								'error 40\d', # any digit so it can be 404 or 400 whatever
								'not found',
								'cannot be found',
								'could not find',
								'can’t find',
								'bad request',
								'server error',
								'temporarily unavailable',
								'not exist',
								'unable to open',
								'check your spelling',
								'an error has occurred',
								);
	foreach my $errorCheck (@PosibleErrorStrings){
		if($CheckResp =~ /$errorCheck/i){
			push(@ErrorStringsFound, "\"$errorCheck\" ");
		}
	}
	if(defined $ErrorStringsFound[0]){ # if the page contains multi error just put em into the same string
		print "+ Item \"$checkURL\" Contains text(s): @ErrorStringsFound MAYBE a False Positive!\n";
	}
	
	while(defined $ErrorStringsFound[0]){  pop @ErrorStringsFound;  } # saves the above if for the next go around
	
	
	unless(defined $auth){ # that would make a SAD panda :(
		my @PosibleLoginPageStrings = ('login','log-in','sign( |)in','logon',);
		foreach my $loginCheck (@PosibleLoginPageStrings){
			if($CheckResp =~ /<title>.*?$loginCheck/i){
				print "+ Item \"$checkURL\" Contains text: \"$loginCheck\" in the title MAYBE a Login page\n";
			}
		}
	}
	
	#determine content-type
	my $indexContentType;
	my $IndexPage = $resAnalIndex->as_string();
	my @indexheadersChop = split("\n\n", $IndexPage);
	my @indexHeaders = split("\n", $indexheadersChop[0]); # tehe i know...
	
	foreach my $indexHeader (@indexHeaders){
		if($indexHeader =~ /content-type:/i){
			$indexContentType = $indexHeader;
		}
	}
	
	# check page size
	my $IndexLength = length($resAnalIndex->as_string()); # get byte length of page
	if(length($IndexLength) > 999) { chop $IndexLength;chop $IndexLength; } # make byte length aproximate
	
	my $respLength = length($CheckResp);
	if(length($respLength) > 999) { chop $respLength;chop $respLength; }
	
	if($IndexLength = $respLength and $CheckResp =~ /$indexContentType/i){ # the content-type makes for higher confindence
		print "+ Item \"$checkURL\" is about the same length as root page / This is MAYBE a redirect\n" unless $checkURL eq "/";
	}
	
	# check headers
	my @analheadersChop = split("\n\n", $CheckResp);
	my @analHeaders = split("\n", $analheadersChop[0]); # tehe i know...
	
	foreach my $analHString (@analHeaders){ # method used in sub Standard is not used because of custom msgs and there's not more then 2 headers per msg so why bother
	
		#the page is empty?
		if($analHString =~ /Content-Length: (0|1)$/i){
			print "+ Item \"$checkURL\" contains header: \"$analHString\" MAYBE a False Positive or is empty!\n";
		}
		
		#auth page checking
		if($analHString =~ /www-authenticate:/i){
			print "+ Item \"$checkURL\" contains header: \"$analHString\" Hmmmm\n";
		}
		
		#a hash?
		if($analHString =~ /Content-MD5:/i){
			print "+ Item \"$checkURL\" contains header: \"$analHString\" Hmmmm\n";
		}
		
		#redircted me?
		if($analHString =~ /refresh:/i){
			print "+ Item \"$checkURL\" - looks like it redirects. header: \"$analHString\"\n";
		}
		
		if($analHString =~ /http\/1.1 30(1|2|7)/i){
			print "+ Item \"$checkURL\" - looks like it redirects. header: \"$analHString\"\n";
		}
		
		if($analHString =~ /location:/i){
			my @checkLocation = split(/:/,$analHString);
			my $lactionEnd = $checkLocation[1];
			unless($lactionEnd =~ /$checkURL/i){ 
				print "+ Item \"$analHString\" does not match the requested page: \"$checkURL\" MAYBE a redirect?\n";
			}
		}
		
	}
	
	
	if(defined $interesting or defined $nin or defined $e){
		&interesting($CheckResp,$checkURL,$indexContentType);
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
		$checkMsgDir = undef;
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
		$checkDir = undef;
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
		&bannerGrab();
		sub bannerGrab{
			my @checkHeaders = (
								'server:',
								'x-powered-by:',
								'x-meta-generator:',
								'x-meta-framework:',
								'x-meta-originator:',
								'x-aspnet-version:',
								);
		

			my $resP = $ua->get("http://$Host/");
			my $headers = $resP->as_string();
			
			&analyzeResponse($resP->as_string() ,"/");
			
			my @headersChop = split("\n\n", $headers);
			my @headers = split("\n", $headersChop[0]);
			
			foreach my $HString (@headers){
				foreach my $checkSingleHeader (@checkHeaders){
					if($HString =~ /$checkSingleHeader/i){
						print "+ Server Info in Header: \"$HString\"\n";
					}
				}
			}
		}
		
		#robots.txt
		&Robots();
		sub Robots{
			my $roboTXT = $ua->get("http://$Host/robots.txt");
			unless($roboTXT->is_error){
				&analyzeResponse($roboTXT->as_string() ,"/robots.txt");
				
				my $Opt = &PromtUser("+ robots.txt found! This could be interesting!\n+ would you like me to display it? (y/n) ? ");

				if($Opt =~ /y/i){
					print "+ robots.txt Contents: \n";
					my $roboContent = $roboTXT->decoded_content;
					while ($roboContent =~ /\n\n/) {	$roboContent =~ s/\n\n/\n/g;	} # cleaner. some robots have way to much white space
					while ($roboContent =~ /\t/) {	$roboContent =~ s/\t//g;	}
					
					print $roboContent . "\n";
				}
			}
		}
		
		
		#lilith 6.0A rework of sub indexable with a cupple additions.
		
		my @CommonDIRs = (
							'/images',
							'/imgs',
							'/img',
							'/icons',
							'/home',
							'/pictures',
							'/main',
							'/css',
							'/style',
							'/styles',
							'/docs',
							'/pics',
							'/_',
							'/thumbnails',
							'/thumbs',
							'/scripts',
							'/files',
							'/js',
							'/site',
							);
		&checkOpenDirListing(@CommonDIRs);
		
		sub checkOpenDirListing{
			my (@DIRlist) = @_;
			foreach my $dir (@DIRlist){

				my $IndexFind = $ua->get("http://$Host" . $dir);
					
				# Apache
				if($IndexFind->content =~ /<H1>Index of \/.*<\/H1>/i){
					# extra checking (<a.*>last modified</a>, ...)
					print "+ Directory indexing found in \"$dir\"";
					&analyzeResponse($IndexFind->as_string() ,$dir);
				}

				# Tomcat
				if($IndexFind->content =~ /<title>Directory Listing For \/.*<\/title>/i and $IndexFind->content =~ /<body><h1>Directory Listing For \/.*<\/h1>/i){
					print "+ Directory indexing found in \"$dir\"\n";
					&analyzeResponse($IndexFind->as_string() ,$dir);
				}

				# iis
				if($IndexFind->content =~ /<body><H1>$Host - $dir/i){
					print "+ Directory indexing found in \"$dir\"\n";
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
		my @badexts;
		my @webExtentions = ('.php','.html','.htm','.aspx','.asp','.jsp','.cgi','.xml');
		foreach my $Extention (@webExtentions){
			my $testErrorString = &genErrorString();
			my $check200 = $ua->get("http://$Host/$testErrorString" . $Extention);
			
			if($check200->is_success){
				push(@badexts, "\"$Extention\" ");
			}
		}
		if(defined $badexts[0]){ # if the page contains multi error just put em into the same string
			print "+ INTENTIONALLY bad requests sent with the file Extention(s) @badexts responded with odd status codes. any results from this server with those files extention(s) may be void\n";
		}
	
		while(defined $badexts[0]){  pop @badexts;  } # saves the above if for the next go around
		

		#does the site have a mobile page?
		my $MobileUA = LWP::UserAgent->new;
		$MobileUA->agent('Mozilla/5.0 (iPhone; U; CPU like Mac OS X; en) AppleWebKit/420+ (KHTML, like Gecko) Version/3.0');
		my $mobilePage = $MobileUA->get("http://$Host/");
		my $regularPage = $ua->get("http://$Host/");
		
		unless($mobilePage->content() eq $regularPage->content()){
			print "+ index page reqested with an Iphone UserAgent is diferent then with a regular UserAgent. This Host may have a mobile site\n";
		}
		$mobilePage = undef; $regularPage = undef;
		
		# is ssl there?
		$ua->ssl_opts(verify_hostname => 1);
		
		my $sslreq = $ua->get("https://$Host/");
		unless(length($sslreq->content) == 0 or $sslreq->is_error){
			print "+ $Host is SSL enabled\n";
		}
		$sslreq = undef;
		
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
	my @cmsPluginDBlist;
	if(defined $e){$cmsPlugins = "all";}
	
	if($cmsPlugins =~ /dp/i){
		push(@cmsPluginDBlist, 'DB/drupal_plugins.db');
	}
	
	if($cmsPlugins =~ /jm/i){
		push(@cmsPluginDBlist, 'DB/joomla_plugins.db');
	}
	
	if($cmsPlugins =~ /wp/i){
		push(@cmsPluginDBlist, 'DB/wp_plugins.db');
	}
	
	if($cmsPlugins =~ /all/i ){
		@cmsPluginDBlist = ('DB/drupal_plugins.db', 'DB/joomla_plugins.db', 'DB/wp_plugins.db');
	}
	
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
	my @FilesAndDirsDBlist = ('DB/raft-small-files.db','DB/raft-small-directories.db',);
	
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

	sub WScontent{
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
	}
	
	&WScontent();
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
		&dataBaseScan($cmsDirAndMsg,'Web service Found (cms)'); #this func can only be called when the DB uses the /dir;msg format
	}

	close(cmsDB);
}




sub interesting{ # look for DBs, dirs, login pages, and emails and such
	my $mineShaft = shift;
	my $mineUrl = shift;
	my $PageContentType = shift;
	
	my @InterestingStringsFound;
	my @IndexData;
	
	my @interestingStings = ( # much thiner cuz was to general and verbose
							'\/cgi-bin',
							'\/wp-content\/plugins\/',
							'\/components\/',
							'\/modules\/',
							'\/templates\/',
							'_vti_',
							'@.*?\.(com|org|net|tv|uk|au|edu|mil|gov)', #emails
							'<!--#', #SSI
							);
	
	foreach my $checkInterestingSting (@interestingStings){
		if($PageContentType =~ /text\/html/i){
			my @IndexData = split(/</,$mineShaft);
		} else {
			my @IndexData = split(/\n/,$mineShaft);
		}
		
		foreach my $splitIndex (@IndexData){
			if($splitIndex =~ /$checkInterestingSting/i){
				while($splitIndex =~ /(\n|\t|  )/){
					$splitIndex =~ s/\n/ /g;
					$splitIndex =~ s/\t//g;
					$splitIndex =~ s/  / /g;
				}
				# the split chops off < so i just stick it in there to make it look pretty
				push(@InterestingStringsFound, "<$splitIndex\n\t");
			}
		
		}


		
		if(defined $InterestingStringsFound[0]){ # if the page contains multi error just put em into the same string
			print "+ Interesting text found in \"$mineUrl\" @InterestingStringsFound\n";
		}
		
		while(defined $InterestingStringsFound[0]){  pop @InterestingStringsFound;  } # saves the above if for the next go around
	
	}
	$mineShaft = undef;
}




sub FingerPrint{
	print "+ NOTE: -Fp is a bit unrefined and will be improved over time\n";
	
	my @Weight; # i'll use this more in the future
		
	my $HTTPdelReq = HTTP::Request->new(DELETE => "http://$Host");
	my $DELETEres = $ua->request($HTTPdelReq);
	my $DELcontent = $DELETEres->as_string();
	
	my @DELcontentSplit = split(/\n/, $DELcontent);
	my $HTTPresField = $DELcontentSplit[0];
	
	my @DELresp = ('HTTP\/1\.1 405 Method Not Allowed;Apache', 'HTTP\/1\.1 302 Found;Apache','HTTP\/1\.1 403 Forbidden;Microsoft-IIS','HTTP\/1\.1 405 Not Allowed;nginx');
	foreach my $PrintHTTPfield (@DELresp){
		my @DELhttpMSGSplit = split(/;/, $PrintHTTPfield);
		my $MatchHTTPError = $DELhttpMSGSplit[0];
		my $DELdaemon = $DELhttpMSGSplit[1];
		
		if ($HTTPresField =~ /$MatchHTTPError/i){
			print "+ HTTP Fingerprint - DELETE Method concludes: $DELdaemon\n";
		}
		
	}


	# -Eb code repurposed
	my $getErrorString = &genErrorString();
	my $_404response = $ua->get("http://$Host/$getErrorString");

	if($_404response->is_error) {
		my $siteHTML = $_404response->decoded_content;
		
		$siteHTML =~ s/<.*?>//g;
			
		if($siteHTML =~ /apache\//i){
			print "+ HTTP Fingerprint - 404 Method concludes: Apache\n";
		}
	
		if($siteHTML =~ /Microsoft Product Support Services/i){
			print "+ HTTP Fingerprint - 404 Method concludes: Microsoft-IIS\n";
		}
		
		if($siteHTML =~ /nginx\//){
			print "+ HTTP Fingerprint - 404 Method concludes: nginx\n";
		}
	}
	
	# I'm having trouble with this code.
	#my $Dconf = 0;my $daemon;my $Resdump = $resAnalIndex->as_string();my @orderHeadersChop = split("\n\n", $Resdump);my @orderHeaders = split("\n", $orderHeadersChop[0]);open(FPDB,'+< DB/http_finger-print.db');my @FPsDataBaseSplit = <FPDB>;foreach my $TestFP (@FPsDataBaseSplit){if($TestFP eq '{'){next;} else {unless($TestFP eq '}'){if($TestFP =~ /Daemon-/){$TestFP =~ s/Daemon-//; #leave just name remaining $daemon = $TestFP;chomp $daemon;next;}foreach my $examineHeader (@orderHeaders){if($examineHeader =~ /$TestFP/i){$Dconf++;} else {}}push(@Weight,"$daemon;$Dconf");}}}close(FPDB);
}

sub Ninja{
	&bannerGrab();
	sleep(int((rand(3)+2))); # pause for a random amount of time
	&faviconMD5();
	sleep(int((rand(3)+2)));
	&Robots();
	sleep(int((rand(3)+2)));
	&WScontent();
}
