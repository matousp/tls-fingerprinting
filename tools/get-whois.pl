#!/usr/local/bin/perl -w

#
# get-whois.pl: resolves the input list IPv4 addresses using WHOIS service 
#
# format: get-whois.pl -f <input_file> -out <output_file>
#
#       input_file: a list of IPv4 addresses, each address is on a separated line      
#
#       output_file: a CSV file of resolved IPv4 addresses and owner description obtained from whois
#                      <IPv4 address>;<owner description>
#                   - owner description is take from the following WHOIS fields: orgname, organization, role, desc, netname
#                   - NetName follows separated by the comme with Country in brackets if present
#                     E.g.: 95.216.2.172;Hetzner Online GmbH, HETZNER-hel1-dc2 (DE)
#
#      the progress of resolution is printed on the stdout
#
# Important note: WHOIS resolution can be very long, so it is better to run this script offline 
#
# Date: 30/5/2024
# (c) Petr Matousek, Brno University of Technology, matousp@fit.vutbr.cz
# Created as a part of the FETA project (2022-2025)
#
# Last update: 31/5/2024
#
# changes:

use strict;
use Getopt::Long;
use IO::Handle;
use Net::Whois::IP qw(whoisip_query);

#
# global vars
#
my ($whois_db);  # a hash of IP addresses mapped to WHOIS orgnames

&Main;

#
# sub Main
#
sub Main {
    my ($filename,$FILE,$outfile, $OUTFILE);
    my ($srcIP);
    my ($row,$lineno);
    my ($separator)=";";
    my ($response,$org);   # result of whois query
    
    GetOptions("file=s" => \$filename, "out=s" => \$outfile);
    
    if (!$filename or !$outfile){
	print "Format: $0 -f <file_name> -out <outfile.csv>\n";
	exit 1;
    }

    if (!open ($FILE,$filename)){
	print "Cannot open file '$filename'\n";
	exit 1;
    }

    if (!open ($OUTFILE,'>',$outfile)){
	print "Cannot open file '$outfile' for writing\n";
	exit 1;
    }

    $OUTFILE->autoflush(1);   # disable buffering
    
    # reads the input file with IPv4 addresses on each line
    $lineno = 0;
    while (<$FILE>){
	$lineno++;
	$row = $_;
	chop($row);
        if ($row  =~ /(.+)/){
	    $srcIP = $1;
	    print "* resolving $srcIP to $outfile\n";
	    if ($whois_db->{$srcIP}){              # if an entry already exists in the whois db
		$org = $whois_db->{$srcIP};
	    } else {                               # the IP address is not in the db -> whois resolution needed
		my $response = whoisip_query($srcIP);
#		foreach (sort keys(%{$response}) ){    # check all available WHOIS fields
#		    print "  $_ $response->{$_} \n";
#		}
		if ($response->{'org-name'}){          # Whois output format is variable in order of preference
		    $org = $response->{'org-name'};
		} elsif ($response->{'OrgName'}){
		    $org = $response->{'OrgName'};
		} elsif ($response->{'Organization'}){
		    $org = $response->{'Organization'};
		} elsif ($response->{'role'}){
		    $org = $response->{'role'};
		} elsif ($response->{'descr'}){
		    $org = $response->{'descr'};
		} elsif ($response->{'netname'}){
		    $org = $response->{'netname'};
		} elsif ($response->{'NetName'}){
		    $org = $response->{'NetName'};
		} else {
		    $org = "unknown";
		}
		if ($response->{'netname'}){            # add netname or NetName if exists 
		    $org = $org.", ".$response->{'netname'};
		} elsif ($response->{'NetName'}){       
		    $org = $org.", ".$response->{'NetName'};
		}
		
		if ($response->{'country'}){       # add country code to the org name if available
		    $org = $org." (".$response->{'country'}.")";
		}
		$whois_db->{$srcIP} = $org;        # save the resolve address to the whois db
	    }
	    print $OUTFILE $srcIP.$separator.$org."\n";
	} else {
	    print "Unexpected input format on line $lineno\n";
	    exit 1;
	}
    } # end while
    close($OUTFILE);
}
