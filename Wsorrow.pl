#!/usr/bin/perl 

# Copyright 2012 Dakota Simonds
# A small portion of this software is from Lilith 6.0A and is Sited.
# sub MatchDirIndex (very modified) Copyright (c) 2003-2005 Michael Hendrickx

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

#VERSION 1.4.1

BEGIN { # it seems to load faster. plus outputs the name and version faster
	print "\n[+] Web-Sorrow v1.4.1 remote enumeration security tool\n";

	use LWP::UserAgent;
	use LWP::ConnCache;
	use HTTP::Request;
	use HTTP::Response;
	use Getopt::Long qw( GetOptions );
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
		$ua->max_redirect(1); # if set to 0 it messes up directory indexing
		$ua->agent("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:0.9.3) Gecko/20010801");


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
			"Df"      => \my $Df, #default files
			"d=s"     => \my $Dir,
			"np"      => \my $noPasive,
		);
		
		
		# usage
		if($Host eq "none") {
			usage();
			exit();
		}

		if($Host =~ /http(s|):\/\//i) { #check host input
			$Host =~ s/http(s|):\/\///gi;
			$Host =~ s/\/.*//g;
		}
		
		

		foreach ( split(/;/, $Host) ){ # if imput is more than one host do banner for each
			print "[+] Host: $_\n";
		}
		
			
		if(defined $ProxyServer) {
			print "[+] Proxy: $ProxyServer\n";
		}
		print "[+] Start Time: " . localtime() . "\n";
		print "=" x 70 . "\n";



		
		if(defined $UserA) {
			$ua->agent($UserA);
		}

		if(defined $ProxyServer) {
			$ua->proxy('http',"http://$ProxyServer"); # always make sure to put this first, lest we send un-proxied packets
		}
		if(defined $RangHeader) {
			print "[-] -R is experimental\n";
			$ua->default_headers->header('Range' => 'bytes 0-1');
		}
		if(defined $shdw) {
			print "[-] The cached pages MAYBE out of date so the results maynot be perfect\n";
			$Host = ShadowScan();
			if(defined $SubDom) {
				print "[x] -Sd does not work with -Shadow... disabling\n";
				undef($SubDom);
			}
		}
		
		if(defined $Dir) {
			print "[+] All reported items are within $Dir\n";
		}
		
		if($Host =~ ';'){
			my @Hosts = split(/;/, $Host); 

			foreach(@Hosts) {
				$Host = $_;
				unless($Port == 80) {
					$Host = $Host . ":$Port";
				}
				
				print "=" x 70 . "\n[+] Scanning Host: $Host\n";
				print "=" x 70 . "\n";
				startScan();
			}
		} else {
			unless($Port == 80) {
				$Host = $Host . ":$Port";
			}
			startScan(); 
		}
		
		
		sub startScan{ #triger scans
			unless(defined $nin) { checkHostAvailibilty(); } # skip if --ninja or --shadow for more stealth
			
			if(defined $Dir) {
				chop($Dir) if $Dir =~ m/\/$/;
				$Dir = "/" . $Dir unless $Dir =~ m/^\//;
				$Host = $Host . $Dir;
			}
			
			# in order of aproximate finish times
			if(defined $S)         { Standard();            }
			if(defined $nin)       { Ninja();               }
			if(defined $auth)      { auth();                }
			if(defined $Df)        { defaultFiles();        }
			if(defined $cmsPlugins){ cmsPlugins();          }
			if(defined $Ws)        { webServices();         }
			if(defined $SubDom)    { SubDomainBF();         }
			if(defined $Fd)        { FilesAndDirsGoodies(); }
			if(defined $DirB)      { Dirbuster();           }
			if(defined $e)         { runAll();              }
			
			
			
			sub runAll{
				Standard();
				auth();
				defaultFiles();
				webServices();
				SubDomainBF();
				cmsPlugins();
				FilesAndDirsGoodies();
				Dirbuster();
			}
		}



		print "=" x 70 . "\n";
		print "[+] done :'(  -  Finsh Time: " . localtime . "\n";






#----------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------


# non scanning subs for clean code and speed 'n stuff

sub usage{

print q{
Remember to check for updates http://web-sorrow.googlecode.com/

Usage: perl Wsorrow.pl [HOST OPTIONS] [SCAN(s)]

HOST OPTIONS:
    -host [host]     -- Defines host to scan or a list separated by semicolons
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
    -Fd      --  Scan for common interesting files and dirs (Bruteforce)
    -Sd      --  BruteForce Subdomains (host given must be a domain. Not an IP)
    -Ws      --  Scan for Web Services on host such as: cms version info, 
                 blogging services, favicon fingerprints, and hosting provider
    -Db      --  BruteForce Directories with the big dirbuster Database
    -Df      --  Scan for default Apache files
    -e       --  Everything. run all scans


OTHER:
    -I       --  Passively find interesting strings in responses (results may
                 contain partial html)
    -ninja   --  A light weight and undetectable scan that uses bits and
                 peices from other scans (it is not recomended to use with any
                 other scans if you want to be stealthy. See readme.txt)
    -ua [ua] --  Useragent to use. put it in quotes. (default is firefox linux)
    -R       --  Only request HTTP headers (ranges and head reqs).
                 This is much faster but some features and capabilities
                 may not work with this option. But it's perfect when
                 you only want to know if something exists or not.
                 like in -auth or -Fd
    -Shadow  --  Request pages from Google cache instead of from the Host.
                 (mostly for just -I otherwise it's unreliable)
    -d [dir] --  Only scan within this directory
    -np      --  Don't do passive tests: banner grabbing, Dir indexing,
                 Odd http status, Error pages/strings (be less verbose)

EXAMPLES:
    perl Wsorrow.pl -host scanme.nmap.org -S
    perl Wsorrow.pl -host nationalcookieagency.mil -Cp dp,jm -ua "script w/ the munchies"
    perl Wsorrow.pl -host thediamondclub.com -d /wordpress -Cp wp
    perl Wsorrow.pl -host 66.11.227.35 -port 8080 -proxy 129.255.1.17:3128 -S -Ws -I 
};

}

sub checkHostAvailibilty{
	my $CheckHost1 = $ua->get("http://$Host/");
	my $CheckHost2 = $ua->get("http://$Host");
	analyzeResponse($CheckHost2->decoded_content, "/");
	
	if($CheckHost2->is_error and $CheckHost1->is_error) {
		print "[-] Host: $Host appears to be offline or unavailble. Continuing...\n";
	}
}

sub PromtUser{ # Yes or No?
	my $PromtMSG = shift; # i find the shift is much sexyer then then @_
	
		print $PromtMSG;
		$Opt = <stdin>;
		return $Opt;
}

sub analyzeResponse{ # heres were most of the smart is...
	my $CheckResp = shift;
	my $checkURL = shift;
	
		unless($checkURL =~ m/^\//) {
			$checkURL = "/" . $checkURL; # makes for good output
		}
		
		
		my $FoundErrors = 0;
		#False Positive checking based on page content
		my @PosibleErrorStrings = (
									'404 error',
									'404 page',
									'error 404', 
									'not found',
									'cannot be found',
									'could not find',
									'can\'t find',
									'cannot found', # incorrect english but i'v seen it before
									'could not be found',
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
		
		my @ErrorStringsFound;
		foreach my $errorCheck (@PosibleErrorStrings){
			if($CheckResp =~ m/$errorCheck/i) {
				push(@ErrorStringsFound, "\"$errorCheck\" ");
				$FoundErrors = 1;
			}
		}
		if($FoundErrors) { # if the page contains multi error just put em into the same string
			print "[-] Item \"$checkURL\" Contains text(s): @ErrorStringsFound MAYBE a False Positive!\n";
		}
		undef(@ErrorStringsFound); # emty array. saves the above if for the next go around
			
			
		# Login Page detection
		unless(defined $auth) { # that would make a SAD panda :(
			my @PosibleLoginPageStrings = ('login','log-in','sign( |)in','logon',);
			foreach my $loginCheck (@PosibleLoginPageStrings){
				if($CheckResp =~ m/<title>.*$loginCheck.*<\/title>/i) {
					print "[+] Item \"$checkURL\" Contains text: \"$loginCheck\" in the title MAYBE a Login page\n";
				}
			}
		}
		

		my @analHeaders = getHeaders($CheckResp); 
			
		foreach my $analHString (@analHeaders){
			study $analHString;
			#the page is empty?
			if($analHString =~ m/Content-Length:( |)(0|1|2|3|4|5|6)$/i){  print "[-] Item \"$checkURL\" contains header: \"$analHString\" MAYBE a False Positive or is empty!\n";  }
			
			#auth page checking
			if($analHString =~ m/www-authenticate:/i){  print "[+] Item \"$checkURL\" contains header: \"$analHString\" Hmmmm\n";  }
			
			#a hash?
			if($analHString =~ m/Content-MD5:/i){  print "[+] Item \"$checkURL\" contains header: \"$analHString\" Hmmmm\n";  }
			
			#redircted me?
			if($analHString =~ m/refresh:( |)\w/i){  print "[-] Item \"$checkURL\" looks like it redirects. header: \"$analHString\"\n";  }
			
			if($analHString =~ m/HTTP\/1\.(1|0) 30(1|2|7)/i){ print "[-] Item \"$checkURL\" looks like it redirects. header: \"$analHString\"\n"; }
				
			if($analHString =~ m/location:/i){
				my @checkLocation = split(/:/,$analHString);
				my $lactionEnd = $checkLocation[1];
				unless($lactionEnd =~ m/($checkURL|index\.)/i){ 
					print "[-] Item \"$analHString\" does not match the requested page: \"$checkURL\" MAYBE a redirect?\n";
				}
			}
		}
		
		#this part is for extra (passive) tests
		
		unless(defined $noPasive) {
			if(defined $interesting or defined $nin or defined $e) {
				#determine content-type
				my $respContentType;
				my @indexHeaders = getHeaders($CheckResp);
			
				foreach my $indexHeader (@indexHeaders){
					if($indexHeader =~ m/content-type:/i) {
						$respContentType = $indexHeader;
					}
				}
				undef(@indexHeaders);
				interesting($CheckResp,$checkURL,$respContentType); # anything intsting here?
			}

			MatchDirIndex($CheckResp,$checkURL);
			
			if(defined $Ws) {
				WScontent($CheckResp);
			}
			
			bannerGrab($CheckResp);
		}
		
		$CheckResp = undef;
}

sub genErrorString{
	my $errorStringGGG = "";
	for($i = 0;$i < 20;$i++) {
		$errorStringGGG .= chr((int(rand(93)) + 33)); # random 20 bytes to invoke 404 sometimes 400
	}
	
	$errorStringGGG =~ s/(#|&|\?|\/|\[|\])//g; #strip anchors and q stings and such
	return $errorStringGGG;
}

sub getHeaders{ #simply extract http headers
	my $rawFullPage = shift;
	
		my @headersChop = split("\n\n", $rawFullPage);
		my @HeadersRetu = split("\n", $headersChop[0]);
		
		undef($rawFullPage);
		undef(@headersChop);
		
		return(@HeadersRetu);
}

sub oddHttpStatus{ # Detect when there an odd HTTP status also other headers
	my $StatusToMine = shift;
	my $StatusFrom = shift;
		
		unless($StatusFrom =~ m/^\//) {
			$StatusFrom = "/" . $StatusFrom; # makes for good output
		}
		
		my @StatMine = split("\n",$StatusToMine);
		my $StatCode = $StatMine[0];
		study $StatCode;
		
		if($StatCode =~ m/HTTP\/1\.(0|1) 401/i) {
			print "[-] Item \"$StatusFrom\" responded with HTTP status: \"401 authentication required\"\n";
		}
		if($StatCode =~ m/HTTP\/1\.(0|1) 403/i) {
			print "[-] Item \"$StatusFrom\" responded with HTTP status: \"403 Forbiden\" (exists but denied access)\n"; 
		}
		if($StatCode =~ m/HTTP\/1\.(0|1) 424/i) {
			print "[-] Item \"$StatusFrom\" responded with HTTP status: \"424 Locked\"\n"; 
		}
		if($StatCode =~ m/HTTP\/1\.(0|1) 429/i) {
			print "[-] Item \"$StatusFrom\" responded with HTTP status: \"429 Too Many Requests\" Try -ninja\n"; 
		}
		if($StatCode =~ m/HTTP\/1\.(0|1) 509/i) {
			print "[-] Item \"$StatusFrom\" responded with HTTP status: \"509 Bandwidth Limit Exceeded\" Try -ninja\n"; 
		}
		
		ErrorStrings($StatusToMine, $StatusFrom);
		
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
			
			if($databaseContext eq "nonSynt" or $databaseContext eq "Synt") {# send req and validate
				
				if ($databaseContext eq "Synt") {
					my ($JustDirDB, $MSG) = split(';',$DataFromDB) ;
					unless($JustDirDB =~ m/^\//) {
						$JustDirDB = "/" . $JustDirDB unless $databaseContext eq "match";
					}
					makeRequest($JustDirDB, $MSG, $scanMSG, $databaseContext); # if i put this code elswere it breaks WFT? vars are being kidnaped!
				} elsif($databaseContext eq "nonSynt") {
					my $JustDirDB = $DataFromDB;
					unless($JustDirDB =~ m/^\//) {
						$JustDirDB = "/" . $JustDirDB unless $databaseContext eq "match";
					}
					makeRequest($JustDirDB, $MSG, $scanMSG, $databaseContext); # if i put this code elswere it breaks WFT? vars are being kidnaped!
				}
			}
		
		
	
		
		if($databaseContext eq "match") {
			my ($MatchDataFromDB, $MSG) = split(';',$DataFromDB);
			
			if($MatchFromCon =~ m/$MatchDataFromDB/i) {
				 foreach my $MatchItemFound (@FoundMatchItems){
					if($MatchItemFound eq $MSG) {
						$FoundBefor = 1; # set true
					}
				}
				push(@FoundMatchItems, $MSG);
			
				unless($FoundBefor) { #prevents double output
					print "[+] $scanMSG: $MSG\n";
				}
			}
		}
}

sub makeRequest{
	my $JustDirDBB = shift;#to lazy to makeup new var names
	my $MSGG = shift;
	my $scanMSGG = shift;
	my $databaseContextt = shift;
	
		my $Testreq = $ua->get("http://$Host" . $JustDirDBB) unless defined $RangHeader;
		if(defined $RangHeader) {
			$Testreq = $ua->head("http://$Host" . $JustDirDBB)
		}
		
		if($Testreq->is_success) {
			print "[+] $scanMSGG: \"$JustDirDBB\"";
			if($databaseContextt eq "Synt") {
				print " - $MSGG\n";
			} else {
				print "\n";
			}
				
			analyzeResponse($Testreq->as_string , $JustDirDBB);
		}
		
		oddHttpStatus($Testreq->as_string(), $JustDirDBB) unless defined $noPasive ; # can't put in repsonceAnalysis cuz of ->is_success
		$Testreq = undef;
		$JustDirDBB = undef;
}

sub bannerGrab{
	my $resP = shift;
	$FoundBefor = 0;

		my @checkHeaders = (
							'server:',
							'x-powered-by:',
							'x-meta-generator:',
							'x-meta-framework:',
							'x-meta-originator:',
							'x-aspnet-version:',
							'via:',
							'MIME-Version:',
							);
		
			
		my @headers = getHeaders($resP);
			
		foreach my $HString (@headers){
			foreach my $checkSingleHeader (@checkHeaders){
			
					if($HString =~ m/$checkSingleHeader/i) {
						foreach my $MatchItemFound (@FoundMatchItems){
							if($MatchItemFound eq $HString) {
								$FoundBefor = 1; # set true
							}
						}
						push(@FoundMatchItems, $HString);
					
						unless($FoundBefor) { #prevents double output
							print "[+] Server Info in Header: \"$HString\"\n";
						}
				}
			}
		}
		$resP = undef;
		undef(@headers);
}

sub MatchDirIndex{
	my $IndexConFind = shift;
	my $dirr = shift;

		# Apache
		if($IndexConFind =~ m/<H1>Index of \/.*<\/H1>/i) {
			print "[+] Directory indexing found in \"$dirr\"\n";
		}

		# Tomcat
		if($IndexConFind =~ m/<title>Directory Listing For \/.*<\/title>/i and $IndexConFind =~ m/<body><h1>Directory Listing For \/.*<\/h1>/i) {
			print "[+] Directory indexing found in \"$dirr\"\n";
		}

		# iis
		if($IndexConFind =~ m/<body><H1>$Host - $dirr/i) {
			print "[+] Directory indexing found in \"$dirr\"\n";
		}
}

sub Robots{
	my $roboTXT = $ua->get("http://$Host/robots.txt");
	unless($roboTXT->is_error) {
		my $Opt = PromtUser("[+] robots.txt found! This could be interesting!\n[?] would you like me to display it? (y/n) ? ");

		if($Opt =~ /y/i) {
			print "[+] robots.txt Contents: \n";
			my $roboContent = $roboTXT->decoded_content;
			while ($roboContent =~ /(\n\n|\t)/) {	$roboContent =~ s/(\n\n|\t)/\n/g;	} # cleaner. some robots have way to much white space
			chomp $roboContent; #prevents duble newlines
				
			if($roboContent =~ /(<!DOCTYPE|<html)/i) {
				print "[x] robots.txt contains HTML. canceling display\n";
			} else {
				print $roboContent . "\n";
			}
		}
	}
	$roboTXT = undef;
	$roboContent = undef;
}

#---------------------------------------------------------------------------------------------------------------
# scanning subs


sub Standard{ #some standard stuff
		bannerGrab($ua->get("http://$Host/")->as_string);
		
		#robots.txt
		Robots();
		
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
			MatchDirIndex($Getind->decoded_content, $IndexDir);
		}
		
		$Getind = undef;
		undef(@findDirIndexing);
	
		
		# laguage checks
		my $LangReq = $ua->get("http://$Host/");
		my @langSpaceSplit = split(/ / ,$LangReq->decoded_content);
		
		my @langGate;
		
		foreach my $lineIDK (@langSpaceSplit){
			if($lineIDK =~ /lang=('|").*?('|")/i) {
				$lineIDK =~ s/(\t|\n)//g; #make pretty
				$lineIDK =~ s/(<.*|>.*)//g; #prevent html from sliping in
				
				unless($lineIDK =~ /lang=('|")('|")/) { # empty?
					print "[+] Page Laguage found: $lineIDK\n";
					last; # somtimes pages have like 4 or 5 so just find one
				}
			}
		}
		$LangReq = undef;
		
		# Some servers just give you a 200 with every req. lets see
		my @badexts;
		my @webExtentions = ('.php','.html','.htm','.aspx','.asp','.jsp','.cgi','.pl','.cfm','.txt','.larywall');
		foreach my $Extention (@webExtentions){
			my $testErrorString = genErrorString();
			my $check200 = $ua->get("http://$Host/$testErrorString" . $Extention);
			
			if($check200->is_success) {
				push(@badexts, "\"$Extention\" ");
			}
		}
		if(defined $badexts[0]) { # if the page contains multi error just put em into the same string
			print "[-] INTENTIONALLY bad requests sent with the file Extention(s) @badexts responded with odd status codes. any results from this server with those files extention(s) may be void\n";
		}
		$check200 = undef;
		undef(@badexts);
		

		#does the site have a mobile page?
		$ua->agent('Mozilla/5.0 (iPhone; U; CPU like Mac OS X; en) AppleWebKit/420+ (KHTML, like Gecko) Version/3.0');
		my $mobilePage = $ua->get("http://$Host/");
		$ua->agent("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:0.9.3) Gecko/20010801"); # set back to regualr mozilla
		my $regularPage = $ua->get("http://$Host/");
		
		unless($mobilePage->decoded_content() eq $regularPage->decoded_content()) {
			print "[+] Index page reqested with an Iphone UserAgent is diferent then with a regular UserAgent. This Host may have a mobile site\n";
		}
		$mobilePage = undef; $regularPage = undef;
		
		if(defined $UserA) { # sets back to defined useragent
			$ua->agent($UserA);
		}
		
		
		# is ssl stuff
		$ua->ssl_opts(verify_hostname => 1);
		
		my $sslreq = $ua->get("https://$Host/");
		if($sslreq->is_success) {
			print "[+] $Host is SSL capable\n";
			
			my @parseSSL = getHeaders($sslreq->as_string);
			foreach my $SSLheader (@parseSSL){
				chomp($SSLheader);
				
				if($SSLheader =~ /client-ssl-cipher:/i) { $SSLheader =~ s/client-ssl-cipher://i; print "[+] SSL Cipher: $SSLheader\n"; }
				if($SSLheader =~ /client-ssl-cert-issuer:/i) {#extract
					$SSLheader =~ s/client-ssl-cert-issuer://i;
					$SSLheader =~ s/.*\/O=//i;
					$SSLheader =~ s/\/.*//;
					
					print "[+] SSL Certificate vendor: $SSLheader\n";
				}
			}
			
		}
		$sslreq = undef;
		$ua->ssl_opts(verify_hostname => 0);

		
		# common sensitive shtuff
		open(FilesAndDirsDBFileS, "<", "DB/small-tests.db");
		
		while(<FilesAndDirsDBFileS>){
			dataBaseScan($_,'',"Sensitive item found",'nonSynt') unless $_ =~ /^#/;;
		}
		
		close(FilesAndDirsDBFileS);

		
		
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
							'manager',
							'system',
							'twighlighsparkle',
							);
		
		foreach my $usrnm (@apcheUserNames){
			my $ApcheUseNmTest = $ua->get("http://$Host/~" . $usrnm);
			
			if($ApcheUseNmTest->code == 200 or $ApcheUseNmTest->code == 403) {
				print  "[+] This server has Apache user accounts enabled. Found User: ~$usrnm\n";
				analyzeResponse($ApcheUseNmTest->as_string() ,"/~$usrnm");
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
			
				if($getThumbs->is_success) {
					print "[+] $CapTumbs found. This suggests the host is running Windows\n";
					analyzeResponse($getThumbs->as_string() ,$CapTumbs);
					goto doneThumbs;
				}
			}
		}
		doneThumbs:
		undef($getThumbs);
}




sub defaultFiles{
	open(defaultFilesDB, "<", "DB/defaultFiles.db");
	
	while(<defaultFilesDB>){
		dataBaseScan($_,'','Default File Found','Synt') unless $_ =~ m/^#/;
	}

	close(defaultFilesDB);
}




sub auth{ # this DB is pretty good but needs more pazzaz
	open(authDB, "<", "DB/login.db");

	while(<authDB>){
		dataBaseScan($_,'','Login Page Found','Synt') unless $_ =~ /^#/;
	}

	close(authDB);
}




sub cmsPlugins{ # parts of Plugin databases provided by: Chris Sullo from cirt.net
	print "[-] -Cp takes awhile....\n";
	my @cmsPluginDBlist;
	if(defined $e) { $cmsPlugins = "all"; }
	
	if($cmsPlugins =~ m/dp/i){
		push(@cmsPluginDBlist, 'DB/drupal_plugins.db');
	}
	
	if($cmsPlugins =~ m/jm/i){
		push(@cmsPluginDBlist, 'DB/joomla_plugins.db');
	}
	
	if($cmsPlugins =~ m/wp/i){
		push(@cmsPluginDBlist, 'DB/wp_plugins.db');
	}
	
	if($cmsPlugins =~ m/all/i ){
		@cmsPluginDBlist = ('DB/drupal_plugins.db', 'DB/joomla_plugins.db', 'DB/wp_plugins.db');
	}
	
	foreach my $cmsPluginDB (@cmsPluginDBlist){
		print "[+] Testing Plugins with Database: $cmsPluginDB\n";
			
		open(cmsPluginDBFile, "<", "$cmsPluginDB");
		
		while(<cmsPluginDBFile>){
			dataBaseScan($_,'','CMS Plugin Found','nonSynt') unless $_ =~ /^#/;
		}

		close(cmsPluginDBFile);

	}


}




sub FilesAndDirsGoodies{ # databases provided by: raft team

	print "[-] -Fd takes awhile....\n";
	my @FilesAndDirsDBlist = ('DB/raft-medium-files.db','DB/raft-medium-directories.db',);
	
	foreach my $FilesAndDirsDB (@FilesAndDirsDBlist){
		print "[+] Testing Files And Dirs with Database: $FilesAndDirsDB\n";
			
		open(FilesAndDirsDBFile, "<", "$FilesAndDirsDB");
		
		while(<FilesAndDirsDBFile>){
			dataBaseScan($_,'','Interesting File or Dir Found','nonSynt') unless $_ =~ /^#/;
		}

		close(FilesAndDirsDBFile);

	}

}




sub webServices{
	sub WScontent{ # match page content with known services related
		my $webServicesTestPage = shift;
		
		open(webServicesDB, "<", "DB/web-services.db");
		
		while(<webServicesDB>){
			dataBaseScan($_,$webServicesTestPage,'Web service Found','match') unless $_ =~ /^#/;
		}

		close(webServicesDB);
	}
	
	WScontent($ua->get("http://$Host/")->decoded_content);
	faviconMD5(); # i'll just make a new sub
	cms();
}




sub faviconMD5{ # thanks to OWASP for favicon fingerprints
	require Digest::MD5;
	
	my @favArry = (
					'favicon.ico',
					'Favicon.ico',
					'images/favicon.ico',
					'images/Favicon.ico',
	);
	
	open(faviconMD5DB, "<", "DB/favicon.db");
	my @faviconMD5db = <faviconMD5DB>;
	
	foreach my $favLocation (@favArry){
		my $favicon = $ua->get("http://$Host/$favLocation");
		
		if($favicon->is_success){
			my $MD5 = Digest::MD5->new;
			my $checksum = $MD5->add($favicon->content)->hexdigest; #make checksum

			foreach my $faviconMD5String (@faviconMD5db){
				dataBaseScan($faviconMD5String,$checksum,'Web service Found (favicon.ico)','match');
			}
			
		}
	}
	
	close(faviconMD5DB);
	undef(@faviconMD5db);
	no Digest::MD5; #unload this module
}




sub cms{ # cms default files with version info
	open(cmsDB, "<", "DB/CMS.db");
	
	while(<cmsDB>){
		dataBaseScan($_,'','Web service Found (cms)','Synt') unless $_ =~ /^#/; #this func can only be called when the DB uses the /dir;msg format
	}
	
	close(cmsDB);
}




sub interesting{ # emails, plugins and such
	my $mineShaft = shift;
	my $mineUrl = shift;
	my $PageContentType = shift;
	my $FoundInter = 0;
	
		$mineShaft =~ s/.*?\n\n//; #remove headers
		
		my @InterestingStringsFound;
		my @IndexData;

		my @interestingStings = (
								'\/cgi-bin;CGI Dir',
								'\/wp-content\/plugins\/;WordPress Plugin',
								'\/wp-includes\/;Wordpress include',
								'\/wp-content\/themes\/;Wordpress theme',
								'\/components\/;Possible Drupal Plugin',
								'\/modules\/;Drupal Plugin',
								'\/templates\/;template',
								'\/_vti_;IIS Default Dir/File',
								'$Host\/~;Apache User Dir', # Apache Account
								'\w@.*?\.(com|org|net|tv|uk|au|ro|ca|xxx|edu|mil|gov|biz|info|int|tel|jobs|co|pro);Email', #emails
								'(\t| |\n)@.*?\.(com|uk|au);maybe Twitter Account',
								'<!--#;Server Side Include', #SSI
								'fb:admins;Facebook fbids',
								'\/.\/cpanel\/.*?\/images\/logo.gif\?service=mail;google mail',
								'<\?php;php code',
								'\/_layouts;Sharepoint',
								'It works!;maybe default apache splash screen',
								);

		foreach my $checkInterestingSting (@interestingStings){
			my ($checkInterestingSting, $InMSG) = split(/;/, $checkInterestingSting);
			
			if($PageContentType =~ /(plain\/text|text\/plain)/i){
				my $splitby = "\n";
			} else {
				my $splitby = ">";
			}
			
			my @IndexData = split(/$splitby/,$mineShaft); # reset if text file

			foreach my $splitIndex (@IndexData){
				study $splitIndex;
				if($splitIndex =~ /$checkInterestingSting/i){
					while($splitIndex =~ /(\n|\t|  )/){ $splitIndex =~ s/(\n|\t|  )/ /g; }
					
					if(length($splitIndex) > 200){ # too big for output
						print "[+] Interesting text ($InMSG) found in \"$mineUrl\" You should manualy review it\n";
						last;
					} else {
						push(@InterestingStringsFound, " \n\n  ($InMSG) \"$splitIndex\"");
						$FoundInter = 1;
					}
				}
			
			}


			
			if($FoundInter){ # if the page contains multi error just put em into the same string
				print "[+] Interesting text found in \"$mineUrl\": @InterestingStringsFound\n";
			}
			
			undef(@InterestingStringsFound); # saves the above if for the next go around
		
		}
		$mineShaft = undef;
}




sub ErrorStrings{ #failing is the key here
	my $CheckCont = shift;
	my $ErrorURI = shift;
	my $FoundBefor = 0;

		my @oddErrStrs = (
							'mysql_error \(( |).*?( |)\);contains a mySQL error',
							'The requested URL \/.* was not found on this server;contains requested URI (possibly vunerable to XSS)',
							'<span><H1>Server Error in .* Application<.*><\/H1>;contains .NET Framework or ASP.NET version info',
							'<hr>.*Apache\/;contains Apache version info NOTE: probably all 404 pages from this server contain this',
							'<hr>.*nginx\/;contains nginx version info NOTE: probably all 404 pages from this server contain this',
							);
		
		foreach my $errorstringMsgandMatch (@oddErrStrs){
			my ($matchErrorSTR, $reportMessage) = split(/;/, $errorstringMsgandMatch);
			
			if($CheckCont =~ m/$matchErrorSTR/i){
				
				foreach my $MatchItemFound (@FoundMatchItems){
					if($MatchItemFound eq $reportMessage){
						$FoundBefor = 1; # set true
					}
				}
				push(@FoundMatchItems, $reportMessage);
			
				unless($FoundBefor){
					print "[+] Error page: \"$ErrorURI\" $reportMessage\n";
				}
			}
		}
	
}




sub Ninja{ # total number of reqs sent: 6
	my $ninjaTestPagee = $ua->get("http://$Host/");
	bannerGrab($ninjaTestPagee->as_string);
	sleep(int((rand(3)+2))); # pause for a random amount of time
	faviconMD5();
	sleep(int((rand(3)+2)));
	Robots();
	sleep(int((rand(3)+2)));
	WScontent($ninjaTestPagee->decoded_content);
}




# directory-list-2.3-big.db is under Copyright 2007 James Fisher
# see Original file in Dirbuster for link to licence
# I did not aid or assist in the creation or production of directory-list-2.3-big.db
sub Dirbuster{

	print "[-] -Db takes awhile.... No joke. Go to the movies or something\n";

	open(DirbustDBFile, "<", "DB/directory-list-2.3-big.db");
	
	while(<DirbustDBFile>){
		dataBaseScan($_,'',"Directory found","nonSynt") unless $_ =~ /^#/;
	}
	
	close(DirbustDBFile);
}




sub SubDomainBF{ #thanks to deepmagic.com [mubix] and Knock for a lot of the DB/SubDomain.db
	print "[-] -Sd takes awhile...\n";
	
	my $DomainOnly = $Host;
	my $FindCount = 0;
	
	if($DomainOnly =~ m/.*?\..*?\./i) { # if subdomain
		$DomainOnly =~ s/.*?\.//; #remove subdomain: blah.ws.com -> ws.com
	}
	
	open(SubDomainDB, "<", "DB/SubDomain.db");
	
	while(<SubDomainDB>){
		chomp $_;
		my $SubDomainToRequest = $_.'.'.$DomainOnly;
		my $TestSubDomain = inet_aton($SubDomainToRequest); # much more relieable then http requests for example smtp.blah.com will not respond with http 
		
		unless($TestSubDomain eq "") {
			print "[+] SubDomain Found: $SubDomainToRequest\n";
			$FindCount++;
		}
		
	}

	close(SubDomainDB);
	
	if($FindCount > 1000) {
		print "[-] The host may have the DNS wildcard configuration which would render those results null and void.\n";
	}
	if($FindCount == 0) {
		print "[-] Could not find any SubDomains on this host\n";
	} else {
		print "[+] $FindCount SubDomains Found\n";
	}

}




sub ShadowScan{
	my $HostMutate = "webcache.googleusercontent.com/search?q=cache:" . "$Host";
	return($HostMutate);
}