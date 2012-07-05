
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

----------------------------------------------------------------------------------------------------------

you need PERL to run this program. I you are on linux or an Apple computer you already have perl.
but if you are on a windows computer you can get it here:
http://www.activestate.com/activeperl
or here
http://strawberryperl.com/

It would also be a good idea to update all your modules

------------------------------------------------------------------------------------------------------------

Main Program:                 Wsorrow.pl
Simple Host discovery tool:   hdt.pl
Dumps HTTP headers:           headerDump.pl
Experimental DNS Tool:        DNSpull.pl

------------------------------------------------------------------------------------------------------------

output categorys

[x]  something has been canceled or stoped
[-]  An issue but not allways an error
[+]  Infromation. usually signifying when something has been found
[?]  Requires user input

------------------------------------------------------------------------------------------------------------

What does it do????

A misconfig, version detection, and server enumeration scanning tool.


Misconfig or misconfiguration: scans for things that should have been disabled or maybe turned off like
apache server-status or directory indexing......

Version detection: Web-sorrow has two basic methods of getting version info. the first is called banner
grabbing and the secound scans for files containing verions information
 
server enumeration: this one is the most general term and it would take a long time to list them all but 
some of the other things web-sorrow does is: SSL Cert enum, CMS plugins, subdomain bruteforce, and more

(and it never stops partying)

------------------------------------------------------------------------------------------------------------

CLEARIFYING SOME THINGS:

In Web-Sorrow -ninja does NOT make other scans stealthy It Itself is a scan that uses very few requests

When using -Cp you can scan multiple or single cms plugins Example: -Cp wp,dp or -Cp wp;dp doesn't matter 
what you seperate it with

When useing -ua You Must use qoutes if it contains whitespace

If you use -e with other scans it will run it twice

Through-out the program i put fakes that aren't supposed to yield a positive. (usualy a refrance to something)
You'll know them when you see them. They should always be at the end of each check if they're tripped

Web-Sorrow is a "safe to run" program. meaning it is not designed attempt to exploit or preform any kind of
injection, DDoS/DoS, CTRF, XSS, or any harmful attacks.

Web-Sorrow is not an enemy to Nikto but a brother. dont pick one or the other.

TIP: to log results to a file: perl Wsorrow.pl -host host.com -S -I >logfile.txt

TIP: it's best to veiw the source of all reported items

------------------------------------------------------------------------------------------------------------
if you like web-sorrow please tell me and your friends
contact me on twitter: @flyinpoptartcat

If your having problems read The frontpage http://code.google.com/p/web-sorrow and if you still don't know
what to do contact me on twitter with address above or email me (you can find it on google code if you pass the 
captcha)

If you want to help please post about Web-sorrow on you blog or website.
If you're posting about Web-Sorrow on you're website please provide link: http://code.google.com/p/web-sorrow/downloads/list
NOT directly to the zip file
i've also included the Web-Sorrow logo in this archive

make sure to check for update's FREQUENTLY http://code.google.com/p/web-sorrow (I'm a very rapid developer)