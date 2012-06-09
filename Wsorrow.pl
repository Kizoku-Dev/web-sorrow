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

#VERSION 1.3.9

BEGIN { # it seems to load faster. plus outputs the name and version faster
	print "\n+ Web-Sorrow v1.3.9(beta) Version detection, misconfig, and enumeration scanning tool\n";

	use LWP::UserAgent;
	use LWP::ConnCache;
	use HTTP::Request;
	use HTTP::Response;
	use Digest::MD5;
	use Getopt::Long;
	use Socket qw( inet_aton );
	use encoding "utf-8";

	use strict;
	use warnings;
}


		my $i;
		my $Opt;
		my $Host = "none";
		my $Port = 80;
		my @FoundMatchItems;
		
		my $ua = LWP::UserAgent->new(conn_cache => 1);
		$ua->conn_cache(LWP::ConnCache->new); # use connection cacheing (faster)
		$ua->timeout(5); # don't wait longer then 5 secs
		$ua->default_headers->header('Accept-Encoding' => 'gzip, deflate');# compresses http responces from host (faster)
		$ua->agent("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.5) Gecko/20031027");


		GetOptions(
			"host=s"  => \$Host, # host ip or domain
			"port=i"  => \$Port, # port number
			"S"       => \my $S, # Standard checks
			"auth"    => \my $auth, # MEH!!!!!! self explanitory
			"Cp=s"    => \my $cmsPlugins, # cms plugins
			"I"       => \my $interesting, # find interesting text
			"Ws"      => \my $Ws, # Web services
			"e"       => \my $e, # EVERYTHINGGGGGGGG
			"proxy=s" => \my $ProxyServer, #use a proxy
			"Fd"      => \my $Fd, # files and dirs
			"ninja"   => \my $nin,
			"Db"      => \my $DirB, # use dirbuster database
			"ua=s"    => \my $UserA, # userAgent
			"Sd"      => \my $SubDom, # subdomain
			"R"       => \my $RangHeader,
			"Shadow"  => \my $shdw,
		);
		
		
		# usage
		if($Host eq "none"){
			&usage();
			exit();
		}

		if($Host =~ /http(s|):\/\//i){ #check host input
			$Host =~ s/http(s|):\/\///gi;
			$Host =~ s/\/.*//g;
		}
		
		unless($Port == 80){
			$Host = $Host . ":$Port";
		}
		
		print "+ Host: $Host\n";

		if(defined $ProxyServer){
			print "+ Proxy: $ProxyServer\n";
		}
		print "+ Start Time: " . localtime() . "\n";
		print "-" x 70 . "\n";





		#triger scans
		if(defined $UserA){
			$ua->agent($UserA);
		}

		if(defined $ProxyServer){
			&proxy(); # always make sure to put this first, lest we send un-proxied packets
		}
		if(defined $RangHeader){
			print "+ -R is experimental\n";
			$ua->default_headers->header('Range' => 'bytes 0-1');
		}
		if(defined $shdw){
			print "+ The cached pages MAYBE out of date so the results maynot be perfect\n";
			$Host = &ShadowScan();
			if(defined $SubDom){
				print "+ -Sd does not work with -Shadow... disabling\n";
				undef($SubDom);
			}
		}
		
		&checkHostAvailibilty() unless defined $nin; # skip if --ninja or --shadow for more stealth
		my $resAnalIndex = $ua->get("http://$Host/");
		
		# in order of aproximate finish times
		if(defined $S){ &Standard(); }
		if(defined $nin){ &Ninja(); }
		if(defined $auth){ &auth(); }
		if(defined $cmsPlugins){ &cmsPlugins(); }
		if(defined $Ws){ &webServices(); }
		if(defined $SubDom){ &SubDomainBF(); }
		if(defined $Fd){ &FilesAndDirsGoodies(); }
		if(defined $DirB){ &Dirbuster(); }
		if(defined $e){ &runAll(); }
		
		
		
		sub runAll{
			&Standard();
			&auth();
			&webServices();
			&SubDomainBF();
			&cmsPlugins();
			&FilesAndDirsGoodies();
			&Dirbuster();
		}




		print "-" x 70 . "\n";
		print "+ done :'(  -  Finsh Time: " . localtime;






#----------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------




# non scanning subs for clean code and speed 'n stuff

sub usage{

print q{
Remember to check for updates http://web-sorrow.googlecode.com/

Usage: perl Wsorrow.pl [HOST OPTIONS] [SCAN(s)]

HOST OPTIONS:
    -host [host]     -- Defines host to use.
    -port [port num] -- Defines port number to use (Default is 80)
    -proxy [ip:port] -- Use an HTTP proxy server


SCANS:
    -S       --  Standard set of scans including: agresive directory indexing,
                 Banner grabbing, Language detection, robots.txt,
                 HTTP 200 response testing, Apache user enum, SSL cert,
                 Mobile page testing, sensitive items scanning, and
                 thumbs.db scanning
    -auth    --  Scan for login pages, admin consoles, and email webapps
    -Cp [dp | jm | wp | all] -- scan for cms plugins.
                 dp = drupal, jm = joomla, wp = wordpress 
    -Fd      --  Scan for common interesting files and dirs
    -Sd      --  BruteForce Subdomains (host given must be a domain. Not an IP)
    -Ws      --  Scan for Web Services on host such as: cms version info, 
                 blogging services, favicon fingerprints, and hosting provider
    -Db      --  BruteForce Directories with the big dirbuster Database
    -e       --  Everything. run all scans


OTHER:
    -I       --  Passively find interesting strings in responses (results may
                 contain partial html)
    -ninja   --  A light weight and undetectable scan that uses bits and
                 peices from other scans (it is not recomended to use with any
                 other scans if you want to be stealthy. See readme.txt)
    -ua [ua] --  Useragent to use. put it in quotes. (default is firefox linux)
    -R       --  Only request HTTP headers. This is much faster but some
                 features and capabilities may not work with this option.
                 But it's perfect when you only want to know if something
                 exists or not. like in -auth or -Fd
    -Shadow  --  Request pages from Google cache instead of from the Host.
                 (mostly for just -I otherwise it's unreliable)


EXAMPLES:
    perl Wsorrow.pl -host scanme.nmap.org -S
    perl Wsorrow.pl -host nationalcookieagency.mil -Cp dp,jm -ua "script w/ the munchies"
    perl Wsorrow.pl -host 66.11.227.35 -port 8080 -proxy 129.255.1.17:3128 -S -Ws -I 
};

}

sub checkHostAvailibilty{
	my $CheckHost1 = $ua->get("http://$Host/");
	my $CheckHost2 = $ua->get("http://$Host");
	&analyzeResponse($CheckHost2->decoded_content, "/");
	
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
	
		unless($checkURL =~ /^\//){
			$checkURL = "/" . $checkURL; # makes for good output
		}
		
		#False Positive checking based on page content
		my @ErrorStringsFound;
		my @PosibleErrorStrings = (
									'404 error',
									'404 page',
									'error 404', 
									'not found',
									'cannot be found',
									'could not find',
									'can’t find',
									'cannot found', # incorrect english but i'v seen it before
									'bad request',
									'server error',
									'temporarily unavailable',
									'not exist',
									'unable to open',
									'check your spelling',
									'an error has occurred',
									'an error occurred',
									'request has been blocked',
									'an automated process',
									'nothing found',
									'just calm down. 420',
									);
		foreach my $errorCheck (@PosibleErrorStrings){
			if($CheckResp =~ /$errorCheck/i){
				push(@ErrorStringsFound, "\"$errorCheck\" ");
			}
		}
		if(defined $ErrorStringsFound[0]){ # if the page contains multi error just put em into the same string
			print "+ Item \"$checkURL\" Contains text(s): @ErrorStringsFound MAYBE a False Positive!\n";
		}
		undef(@ErrorStringsFound); # emty array. saves the above if for the next go around
		
		
		# Login Page detection
		unless(defined $auth){ # that would make a SAD panda :(
			my @PosibleLoginPageStrings = ('login','log-in','sign( |)in','logon',);
			foreach my $loginCheck (@PosibleLoginPageStrings){
				if($CheckResp =~ /<title>.*?$loginCheck<\/title>/i){
					print "+ Item \"$checkURL\" Contains text: \"$loginCheck\" in the title MAYBE a Login page\n";
				}
			}
		}
		foreach my $analHString (@StatMine){
			study $analHString;
			#the page is empty?
			if($analHString =~ /Content-Length: (0|1|2|3)$/i){  print "+ Item \"$checkURL\" contains header: \"$analHString\" MAYBE a False Positive or is empty!\n";  }
			
			#auth page checking
			if($analHString =~ /www-authenticate:/i){  print "+ Item \"$checkURL\" contains header: \"$analHString\" Hmmmm\n";  }
			
			#a hash?
			if($analHString =~ /Content-MD5:/i){  print "+ Item \"$checkURL\" contains header: \"$analHString\" Hmmmm\n";  }
			
			#redircted me?
			if($analHString =~ /refresh:/i){  print "+ Item \"$checkURL\" looks like it redirects. header: \"$analHString\"\n";  }
			
			if($StatCode =~ /HTTP\/1\.(1|0) 30(1|7)/i){ print "+ Item \"$checkURL\" looks like it redirects. header: \"$analHString\"\n"; }
			
			if($analHString =~ /location:/i){
				my @checkLocation = split(/:/,$analHString);
				my $lactionEnd = $checkLocation[1];
				unless($lactionEnd =~ /$checkURL/i){ 
					print "+ Item \"$analHString\" does not match the requested page: \"$checkURL\" MAYBE a redirect?\n";
				}
			}
		}
		
		if(defined $interesting or defined $nin or defined $e){
			#determine content-type
			my $respContentType;
			my @indexHeaders = &getHeaders($CheckResp);
		
			foreach my $indexHeader (@indexHeaders){
				if($indexHeader =~ /content-type:/i){
					$respContentType = $indexHeader;
				}
			}
			undef(@indexHeaders);
			&interesting($CheckResp,$checkURL,$respContentType); # anything intsting here?
		}

		&MatchDirIndex($CheckResp,$checkURL);
		
		if(defined $Ws){
			&WScontent($CheckResp);
		}
		
		$CheckResp = undef;
}

sub genErrorString{
	my $errorStringGGG = "";
	for($i = 0;$i < 20;$i++){
		$errorStringGGG .= chr((int(rand(93)) + 33)); # random 20 bytes to invoke 404 sometimes 400
	}
	
	$errorStringGGG =~ s/(#|&|\?|\/)//g; #strip anchors and q stings and such
	return $errorStringGGG;
}

sub proxy{ # simple!!! i loves it
	$ua->proxy('http',"http://$ProxyServer");
}

sub getHeaders{ #simply extract http headers
	my $rawFullPage = shift;
	
	my @headersChop = split("\n\n", $rawFullPage);
	my @HeadersRetu = split("\n", $headersChop[0]);
	
	return @HeadersRetu;
	$rawFullPage = undef;
	undef(@HeadersRetu);
	undef(@headersChop);
}

sub oddHttpHeaders{ # Detect when there an odd HTTP status also other headers
		my $StatusToMine = shift;
		my $StatusFrom = shift;
		
		unless($StatusFrom =~ /^\//){
			$StatusFrom = "/" . $StatusFrom; # makes for good output
		}
		
		my @StatMine = split("\n",$StatusToMine);
		my $StatCode = $StatMine[0];
		study $StatCode;
		
		if($StatCode =~ /HTTP\/1\.(0|1) 401/i){
			print "+ Item \"$StatusFrom\" responded with HTTP status: \"401 authentication required\"\n";
		}
		if($StatCode =~ /HTTP\/1\.(0|1) 403/i){
			print "+ Item \"$StatusFrom\" responded with HTTP status: \"403 Forbiden\" (exists but denied access)\n"; 
		}
		if($StatCode =~ /HTTP\/1\.(0|1) 424/i){
			print "+ Item \"$StatusFrom\" responded with HTTP status: \"424 Locked\"\n"; 
		}
		if($StatCode =~ /HTTP\/1\.(0|1) 429/i){
			print "+ Item \"$StatusFrom\" responded with HTTP status: \"429 Too Many Requests\" Try -ninja\n"; 
		}
		if($StatCode =~ /HTTP\/1\.(0|1) 509/i){
			print "+ Item \"$StatusFrom\" responded with HTTP status: \"509 Bandwidth Limit Exceeded\" Try -ninja\n"; 
		}

		
		
		
		undef(@StatMine);
		$StatusToMine = undef;
}

sub dataBaseScan{ # use a database for scanning.
	my $DataFromDB = shift;
	my $MatchFromCon = shift;
	my $scanMSG = shift;
	my $databaseContext = shift;
	my $FoundBefor = 0;
	chomp($DataFromDB, $scanMSG);
			
			if($databaseContext eq "nonSynt" or $databaseContext eq "Synt"){# send req and validate
				
				if ($databaseContext eq "Synt"){
					my ($JustDirDB, $MSG) = split(';',$DataFromDB) ;
					unless($JustDirDB =~ /^\//){
						$JustDirDB = "/" . $JustDirDB unless $databaseContext eq "match";
					}
					&makeRequest($JustDirDB, $MSG, $scanMSG); # if i put this code elswere it breaks WFT? vars are being kidnaped!
				} elsif($databaseContext eq "nonSynt"){
					$JustDirDB = $DataFromDB;
					unless($JustDirDB =~ /^\//){
						$JustDirDB = "/" . $JustDirDB unless $databaseContext eq "match";
					}
					&makeRequest($JustDirDB, $MSG, $scanMSG); # if i put this code elswere it breaks WFT? vars are being kidnaped!
				}
			}
		
		
	
		
		if($databaseContext eq "match"){
			my ($MatchDataFromDB, $MSG) = split(';',$DataFromDB);
			
			if($MatchFromCon =~ /$MatchDataFromDB/i){
				 foreach my $MatchItemFound (@FoundMatchItems){
					if($MatchItemFound eq $MatchFromCon){
						$FoundBefor = 1; # set true
					}
				}
				push(@FoundMatchItems, $MSG);
			
				unless($FoundBefor){ #prevents double output
					print "+ $scanMSG: $MSG\n";
				}
			}
		}
}

sub makeRequest{
	my $JustDirDBB = shift;#to lazy to makeup new var names
	my $MSGG = shift;
	my $scanMSGG = shift;
	
			
		my $Testreq = $ua->get("http://$Host" . $JustDirDBB);
			
		if($Testreq->is_success){
			print "+ $scanMSGG: \"$JustDirDBB\"";
			if ($databaseContext eq "Synt"){
				print " - $MSGG\n";
			} else {
				print "\n";
			}
				
			&analyzeResponse($Testreq->as_string(), $JustDirDBB);
		}
		
		&oddHttpHeaders($Testreq->as_string(), $JustDirDBB); # can't put in repsonceAnalysis cuz of ->is_success
		$Testreq = undef;
		$JustDirDBB = undef;
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
								'via:',
								);
		

			my $resP = $ua->get("http://$Host/");
			&analyzeResponse($resP->as_string() ,"/");
			
			my @headers = &getHeaders($resP->as_string());
			
			foreach my $HString (@headers){
				foreach my $checkSingleHeader (@checkHeaders){
					if($HString =~ /$checkSingleHeader/i){
						print "+ Server Info in Header: \"$HString\"\n";
					}
				}
			}
			$resP = undef;
			undef(@headers);
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
					while ($roboContent =~ /(\n\n|\t)/) {	$roboContent =~ s/(\n\n|\t)/\n/g;	} # cleaner. some robots have way to much white space
					chomp $roboContent; #prevents duble newlines
					
					if($roboContent =~ /(<!DOCTYPE|<html|<body)/i){
						print "+ robots.txt contains HTML. canceling display\n";
					} else {
						print $roboContent . "\n";
					}
				}
			}
			$roboTXT = undef;
			$roboContent = undef;
		}
		
		

		my @findDirIndexing =  (
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
						'/doc',
						'/pics',
						'/pic',
						'/_',
						'/thumbnails',
						'/thumbs',
						'/scripts',
						'/files',
						'/js',
						'/site',
						);
						
	
		foreach my $IndexDir (@findDirIndexing){
			my $Getind = $ua->get("http://$Host" . $IndexDir);
			&MatchDirIndex($Getind->decoded_content, $IndexDir);
			
			sub MatchDirIndex {
				my $IndexConFind = shift;
				my $dirr = shift;
				
				# Apache
				if($IndexConFind =~ /<H1>Index of \/.*<\/H1>/i){
					print "+ Directory indexing found in \"$dirr\"\n";
				}

				# Tomcat
				if($IndexConFind =~ /<title>Directory Listing For \/.*<\/title>/i and $IndexConFind =~ /<body><h1>Directory Listing For \/.*<\/h1>/i){
					print "+ Directory indexing found in \"$dirr\"\n";
				}

				# iis
				if($IndexConFind =~ /<body><H1>$Host - $dirr/i){
					print "+ Directory indexing found in \"$dirr\"\n";
				}
			}
		}
		
		$Getind = undef;
		undef(@findDirIndexing);
	
	
		
		# laguage checks
		my $LangReq = $ua->get("http://$Host/");
		my @langSpaceSplit = split(/ / ,$LangReq->decoded_content);
		
		my $langString = 'lang=';
		my @langGate;
		
		foreach my $lineIDK (@langSpaceSplit){
			if($lineIDK =~ /$langString('|").*?('|")/i){
				while($lineIDK =~ /(\t|\n)/){  $lineIDK =~ s/(\t|\n)//; } #make pretty
				if($lineIDK =~ /(<|>|head)/i){ $lineIDK =~ s/(<.*?|>.*?|head)//g; } #prevent html from sliping in
				
				unless($lineIDK =~ /lang=('|")('|")/){ # empty?
					print "+ Page Laguage found: $lineIDK\n";
					last; # somtimes pages have like 4 or 5 so just find one
				}
			}
		}
		
		
		# Some servers just give you a 200 with every req. lets see
		my @badexts;
		my @webExtentions = ('.php','.html','.htm','.aspx','.asp','.jsp','.cgi','.cfm','.txt','.larywall');
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
	
		undef(@badexts);
		

		#does the site have a mobile page?
		$ua->agent('Mozilla/5.0 (iPhone; U; CPU like Mac OS X; en) AppleWebKit/420+ (KHTML, like Gecko) Version/3.0');
		my $mobilePage = $ua->get("http://$Host/");
		$ua->agent("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.5) Gecko/20031027"); # set back to regualr mozilla
		my $regularPage = $ua->get("http://$Host/");
		
		unless($mobilePage->content() eq $regularPage->content()){
			print "+ Index page reqested with an Iphone UserAgent is diferent then with a regular UserAgent. This Host may have a mobile site\n";
		}
		$mobilePage = undef; $regularPage = undef;
		
		if(defined $UserA){ # sets back to defined useragent
			$ua->agent($UserA);
		}
		
		# is ssl stuff
		$ua->ssl_opts(verify_hostname => 1);
		
		my $sslreq = $ua->get("https://$Host/");
		if($sslreq->is_success){
			print "+ $Host is SSL capable\n";
			
			my @parseSSL = &getHeaders($sslreq->as_string);
			foreach my $SSLheader (@parseSSL){
				chomp($SSLheader);
				
				if($SSLheader =~ /client-ssl-cipher:/i){ $SSLheader =~ s/client-ssl-cipher://i; print "+ SSL Cipher: $SSLheader\n"; }
				if($SSLheader =~ /client-ssl-cert-issuer:/i){#extract
					$SSLheader =~ s/client-ssl-cert-issuer://i;
					$SSLheader =~ s/.*\/O=//i;
					$SSLheader =~ s/\/.*//;
					
					print "+ SSL Certificate vendor: $SSLheader\n";
				}
			}
			
		}
		$sslreq = undef;
		$ua->ssl_opts(verify_hostname => 0);

		# common sensitive shtuff
		open(FilesAndDirsDBFileS, "+< DB/small-tests.db");
		my @parseFilesAndDirsDBS = <FilesAndDirsDBFileS>;
		foreach my $JustDirS (@parseFilesAndDirsDBS){
			&dataBaseScan($JustDirS,'',"Sensitive item found",'nonSynt') unless $JustDirS =~ /^#/;;
		}
		close(FilesAndDirsDBFileS);
		undef(@parseFilesAndDirsDBS);
		
		#Apache account name
		my @apcheUserNames = (
							'web',
							'user',
							'guest',
							'root',
							'admin',
							'apache',
							'adminstrator',
							'netadmin',
							'sysadmin',
							'webadmin',
							'twighlighsparkle',
							);
		
		foreach my $usrnm (@apcheUserNames){
			my $ApcheUseNmTest = $ua->get("http://$Host/~" . $usrnm);
			
			if($ApcheUseNmTest->code == 200 or $ApcheUseNmTest->code == 403){
				print  "+ This server has Apache user accounts enabled. Found User: ~$usrnm\n";
				&analyzeResponse($ApcheUseNmTest->as_string() ,"/~$usrnm");
			}
		}
		$ApcheUseNmTest = undef;
		
		#thumbs.db
		my @imageDirs = (
						'/images/',
						'/img/',
						'/imgs/',
						'/pics/',
						'/pictures/',
						'/icons/',
						'/thumbs/',
						'/thumbnails/',
						'/wallpapers/',
						'/iconset/',
						'/',
		);
		
		foreach my $imageDir (@imageDirs){
			foreach my $CapTumbs("thumbs.db","Thumbs.db"){
				$getThumbs = $ua->get("http://$Host".$imageDir.$CapTumbs);
			
				if($getThumbs->is_success){
					print "+ thumbs.db found. This suggests the host is running Windows\n";
					goto doneThumbs;
				}
			}
		}
		doneThumbs:
		undef($getThumbs);
}




sub auth{ # this DB is pretty good but needs more pazzaz
	open(authDB, "+< DB/login.db");
	my @parseAUTHdb = <authDB>;
	
	foreach my $authDirAndMsg (@parseAUTHdb){
		&dataBaseScan($authDirAndMsg,'','Login Page Found','Synt') unless $authDirAndMsg =~ /^#/;
	}

	undef(@parseAUTHdb);
	close(authDB);
}




sub cmsPlugins{ # parts of Plugin databases provided by: Chris Sullo from cirt.net
	print "+ -Cp takes awhile....\n";
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
			&dataBaseScan($JustDir,'','CMS Plugin Found','nonSynt') unless $JustDir =~ /^#/;
		}
		undef(@parsecmsPluginDB);
		close(cmsPluginDBFile);

	}


}




sub FilesAndDirsGoodies{ # databases provided by: raft team

	print "+ -Fd takes awhile....\n";
	my @FilesAndDirsDBlist = ('DB/raft-small-files.db','DB/raft-small-directories.db',);
	
	foreach my $FilesAndDirsDB (@FilesAndDirsDBlist){
		print "+ Testing Files And Dirs with Database: $FilesAndDirsDB\n";
			
		open(FilesAndDirsDBFile, "+< $FilesAndDirsDB");
		my @parseFilesAndDirsDB = <FilesAndDirsDBFile>;
			
		foreach my $JustDir (@parseFilesAndDirsDB){
			&dataBaseScan($JustDir,'','Interesting File or Dir Found','nonSynt') unless $JustDir =~ /^#/;
		}
		undef(@parseFilesAndDirsDB);
		close(FilesAndDirsDBFile);

	}


}




sub webServices{

	sub WScontent{ # match page content with known services related
		my $webServicesTestPage = shift;
		
		open(webServicesDB, "+< DB/web-services.db");
		my @parsewebServicesdb = <webServicesDB>;

		foreach my $ServiceString (@parsewebServicesdb){
			&dataBaseScan($ServiceString,$webServicesTestPage,'Web service found','match') unless $ServiceString =~ /^#/;
		}

		close(webServicesDB);
	}
	
	&WScontent($ua->get("http://$Host/")->content);
	&faviconMD5(); # i'll just make a new sub
	&cms();
}




sub faviconMD5{ # thanks to OWASP for favicon fingerprints
	
	my @favArry = (
					'favicon.ico',
					'Favicon.ico',
					'images/favicon.ico',
	);
	
	foreach my $favLocation (@favArry){
		my $favicon = $ua->get("http://$Host/$favLocation");
		
		if($favicon->is_success){
		
			#make checksum
			my $MD5 = Digest::MD5->new;
			$MD5->add($favicon->content);
			my $checksum = $MD5->hexdigest;
			

			open(faviconMD5DB, "+< DB/favicon.db");
			my @faviconMD5db = <faviconMD5DB>;
			
			
			foreach my $faviconMD5String (@faviconMD5db){
				&dataBaseScan($faviconMD5String,$checksum,'Web service Found (favicon.ico)','match');
			}
			
			undef(@faviconMD5db);
			close(faviconMD5DB);
			no Digest::MD5;
		}
	}
}




sub cms{ # cms default files with version info
	open(cmsDB, "+< DB/CMS.db");
	my @parseCMSdb = <cmsDB>;

	
	foreach my $cmsDirAndMsg (@parseCMSdb){
		&dataBaseScan($cmsDirAndMsg,'','Web service Found (cms)','Synt') unless $cmsDirAndMsg =~ /^#/; #this func can only be called when the DB uses the /dir;msg format
	}
	
	undef(@parseCMSdb);
	close(cmsDB);
}




sub interesting{ # emails, plugins and such
	my $mineShaft = shift;
	my $mineUrl = shift;
	my $PageContentType = shift;
	
	$mineShaft =~ s/.*?\n\n//; #remove headers
	
	my @InterestingStringsFound;
	my @IndexData;

	my @interestingStings = (
							'\/cgi-bin;CGI Dir',
							'\/wp-content\/plugins\/;WordPress Plugin',
							'\/wp-includes\/;Wordpress include',
							'\/components\/;Possible Drupal Plugin',
							'\/modules\/;Drupal Plugin',
							'\/templates\/;template',
							'\/_vti_;IIS Default Dir/File',
							'$Host\/~;Apache User Dir', # Apache Account
							'\w@.*?\.(com|org|net|tv|uk|au|edu|mil|gov|biz|info|int|tel|jobs|co);Email', #emails
							'(\t| |\n)@.*?\.(com|uk|au);maybe Twitter Account',
							'<!--#;Server Side Include', #SSI
							'fb:admins;Facebook fbids',
							'\/.\/cpanel\/.*?\/images\/logo.gif\?service=mail;google mail',
							);

	foreach my $checkInterestingSting (@interestingStings){
		my @InSplit = split(/;/, $checkInterestingSting);
		$checkInterestingSting = $InSplit[0];
		my $InMSG = $InSplit[1]; # set msg
		
		 
		my @IndexData = split(/>/,$mineShaft); #html
		
		if($PageContentType =~ /(plain\/text|text\/plain)/i){
			my @IndexData = split(/\n/,$mineShaft); # reset if text file
		}

		foreach my $splitIndex (@IndexData){
			study $splitIndex;
			if($splitIndex =~ /$checkInterestingSting/i){
				while($splitIndex =~ /(\n|\t|  )/){
					$splitIndex =~ s/(\n|\t|  )/ /g;
				}
				
				if(length($splitIndex) > 200){ # too big for output
					print "+ Interesting text ($InMSG) found in \"$mineUrl\" You should manualy review it\n";
					last;
				} else {
					push(@InterestingStringsFound, " \n\n  ($InMSG) \"$splitIndex\"");
				}
			}
		
		}


		
		if(defined $InterestingStringsFound[0]){ # if the page contains multi error just put em into the same string
			print "+ Interesting text found in \"$mineUrl\": @InterestingStringsFound\n";
		}
		
		undef(@InterestingStringsFound); # saves the above if for the next go around
	
	}
	$mineShaft = undef;
}




sub Ninja{# total number of reqs sent: 6
	&bannerGrab();
	sleep(int((rand(3)+2))); # pause for a random amount of time
	&faviconMD5();
	sleep(int((rand(3)+2)));
	&Robots();
	sleep(int((rand(3)+2)));
	my $webServicesTestPagee = $ua->get("http://$Host/");
	&WScontent($webServicesTestPagee->content);
}




# directory-list-2.3-big.db is under Copyright 2007 James Fisher
# see Original file in Dirbuster for link to licence
# I did not aid or assist in the creation or production of directory-list-2.3-big.db
sub Dirbuster{

	print "+ -Db takes awhile.... No joke. Go to the movies or something\n";

	open(DirbustDBFile, "+< DB/directory-list-2.3-big.db");
	my @parseDirbust = <DirbustDBFile>;
	
	foreach my $JustDir (@parseDirbust){
		&dataBaseScan($JustDir,'',"Directory found","nonSynt") unless $JustDir =~ /^#/;
	}
	undef(@parseDirbust);# unload from RAM
	close(DirbustDBFile);
}




sub SubDomainBF{ #thanks to deepmagic.com [mubix] and Knock for a lot of the DB/SubDomain.db
	print "+ -Sd takes awhile...\n";
	
	my $DomainOnly = $Host;
	my $FindCount = 0;
	
	if($DomainOnly =~ /.*?\..*?\./i){ # if subdomain
		$DomainOnly =~ s/.*?\.//; #remove subdomain: blah.ws.com -> ws.com
	}
	
	open(SubDomainDB, "+< DB/SubDomain.db");
	my @parseSubDomainDB = <SubDomainDB>;
	
	foreach my $subD (@parseSubDomainDB){ # start the scan
		chomp $subD;
		my $SubDomainToRequest = $subD.'.'.$DomainOnly;
		my $TestSubDomain = inet_aton($SubDomainToRequest); # much more relieable then http requests for example smtp.blah.com will not respond with http 
		
		unless($TestSubDomain eq ""){
			print "+ SubDomain Found: $SubDomainToRequest\n";
			$FindCount++;
		}
		
	}

	
	undef(@parseSubDomainDB); # unload from RAM
	close(SubDomainDB);
	
	if($FindCount > 1000){
		print "+ The host may have the DNS wildcard configuration which would render those results null and void.\n";
	}
	if($FindCount == 0){
		print "+ Could not find any SubDomains on this host\n";
	} else {
		print "+ $FindCount SubDomains Found\n";
	}

}




sub ShadowScan{
	my $CacheString = "webcache.googleusercontent.com/search?q=cache:";
	my $HostMutate = $CacheString . "$Host";
	return($HostMutate);
}