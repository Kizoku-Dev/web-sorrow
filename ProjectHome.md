<-- remember to star or recommend web-sorrow (it helps alot)
<br /><b><h3><u>Intro/About:</u></h3></b>
> Web-Sorrow is a perl based tool for misconfiguration, version detection,  enumeration,  and server information scanning. It's entirely focused on Enumeration and collecting Info  on the target server. Web-Sorrow is a "safe to run" program, meaning it is not  designed to be an exploit or perform any harmful attacks.
> <br /> Is there a feature you  want in Web-Sorrow? Is there something that sucks that i can unsuck? Tell me. I  Listen! @flyinpoptartcat
<br />
<b><h3><u>Basic overview of capabilities:</u></h3></b>

> <b>Web Services:</b> a CMS and it's version number, Social media widgets and buttons, Hosting provider, CMS plugins, and favicon fingerprints<br />
> <b>Authentication areas:</b> logins, admin logins, email webapps<br />
> <b>Bruteforce:</b> Subdomains, Files and Directories<br />
> <b>Stealth:</b> with -ninja you can gather valuable info on the target with as few as 6  requests, with -shadow you can request pages via google cache instead of from the  host<br />
> <b>AND MORE:</b> Sensitive files, default files, source disclosure, directory indexing,  banner grabbing (see below for full capabilities)

<br /><b><h3><u>screen shot:</u></h3></b>
<img src='https://pbs.twimg.com/media/BF73ZgiCAAAmyCt.png:large'></img>
<h3><br />
<b><u>Current functionality:</u></b>
</h3>
<h4>HOST OPTIONS:</h4>
> -host `[host`] --  Defines host to scan, a list separated by semicolons, 1.1.1.30-100 type ranges, and 1.1.1.`*` type ranges. You can also use the 1.1.1.30-100 type ranges for domains like www1-10.site.com<br />
> -port `[port num`] -- Defines port number to use (Default is 80)<br />
> -proxy `[ip:port`] -- Use an HTTP, HTTPS, or gopher proxy server<br />


<h4>SCANS:</h4>
> -S -- Standard set of scans including: agresive directory indexing,<br />
> Banner grabbing, Language detection, robots.txt,<br />
> HTTP 200 response testing, Apache user enum, SSL cert,<br />
> Mobile page testing, sensitive items scanning,<br />
> thumbs.db scanning, content negotiation, and non port 80<br />
> server scanning<br />
> -auth -- Scan for login pages, admin consoles, and email webapps<br />
> -Cp `[dp | jm | wp | all`] scan for cms plugins.<br />
> dp = drupal, jm = joomla, wp = wordpress <br />
> -Fd -- Scan for common interesting files and dirs (Bruteforce)<br />
> -Sfd -- Very small files and dirs enum (for the sake of time)<br />
> -Sd -- BruteForce Subdomains (host given must be a domain. Not an IP)<br />
> -Ws -- Scan for Web Services on host such as: cms version info, <br />
> blogging services, favicon fingerprints, and hosting provider<br />
> -Db -- BruteForce Directories with the big dirbuster Database<br />
> -Df `[option`] Scan for default files. platfroms/options: Apache,<br />
> Frontpage, IIS, Oracle9i, Weblogic, Websphere,<br />
> MicrosoftCGI, all (enables all)<br />
> -ninja -- A light weight and undetectable scan that uses bits and<br />
> peices from other scans (it is not recomended to use with any<br />
> other scans if you want to be stealthy. See readme.txt)<br />
> -fuzzsd -- Fuzz every found file for Source Disclosure<br />
> -e -- Everything. run all scans<br />
> -intense -- like -e but no bruteforce<br />
> -I -- Passively scan interesting strings in responses such as:<br />
> emails, wordpress dirs, cgi dirs, SSI, facebook fbids,<br />
> and much more (results may Contain partial html)<br />
> -dp -- Do passive tests on requests: banner grabbing, Dir indexing,<br />
> Non 200 http status, strings in error pages,<br />
> Passive Web services<br />
> -flag `[txt`] -- report when this text shows up on the responses.

<br />

<h4>SCAN SETTINGS:</h4>
> -ua `[ua`] -- Useragent to use. put it in quotes. (default is firefox linux)<br />
> -Rua -- Generate a new random UserAgent per request<br />
> -R -- Only request HTTP headers via ranges requests.<br />
> This is much faster but some features and capabilitises<br />
> May not work with this option. But it's perfect when<br />
> You only want to know if something exists or not.<br />
> Like in -auth or -Fd<br />
> -gzip -- Compresses http responces from host for speed. Some Banner<br />
> Grabbing will not work<br />
> -d `[dir`] -- Only scan within this directory<br />
> -https -- Use https (ssl) instead of http<br />
> -nr -- Don't do responce analisis IE. False positive testing,<br />
> Iteresting headers (other than banner grabbing) if<br />
> you want your scan to be less verbose use -nr<br />
> -Shadow -- Request pages from Google cache instead of from the Host.<br />
> (mostly for just -I otherwise it's unreliable)<br />
> -die -- Stop scanning host if it appears to be offline<br />
> -reject -- Treat this http status code as a 404 error<br />
<br />
web-sorrow also has false positives checking on most of it's requests (it pretty accurate but not perfect)
<br />
<h2>
<u>Examples:</u>
</h2>
> <b>basic:</b> perl Wsorrow.pl -host scanme.nmap.org -S

> <b>stealthy:</b> perl Wsorrow.pl -host scanme.nmap.org -ninja -proxy 190.145.74.10:3128

> <b>scan for login pages:</b> perl Wsorrow.pl -host 192.168.1.1 -auth

> <b>CMS intense scan:</b> perl Wsorrow.pl -host 192.168.1.1 -Ws -Cp all -I

> <b>most intense scan possible:</b> perl Wsorrow.pl -host 192.168.1.1 -e

> <b>dump http headers:</b> perl headerDump.pl

> <b>Check if host is alive:</b> perl hdt.pl -host 192.168.1.1
<br />

<br />
for some reason google code  really likes to double space things so sorry
<br />
<h3>for more info contact: @flyinpoptartcat</h3>