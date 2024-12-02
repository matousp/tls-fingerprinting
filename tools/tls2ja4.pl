#!/usr/local/bin/perl -w
#
# tls2ja4.pl: a parser that reads an CSV output of the tshark, processes TLS Client and Server Hellos
#             from the TLS communication over TCP or QUIC, and computes the JA4 and JA4S hashes
#
# format: tls2ja4.pl -f <input.csv> [-short] [-app AppName] [-ver Version] [-type <0|A|M>] [-res <resolution.csv>] [-whois <whois.csv>]
#
# E.g., tls2ja4.pl -f heodo-extracted.csv -app Heodo -type M -whois whois.txt
#
#             # type: 0 (normal traffic), A (analytics/advertisement), M (malware)
#
#     <input_file> is expected to be tshark output:
#               tshark -r <PCAP file> -T fields -E separator=";" -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport
#              -e udp.srcport -e udp.dstport -e ip.proto -e tls.handshake.type -e tls.handshake.version
#              -e tls.handshake.ciphersuite -e tls.handshake.extension.type -e tls.handshake.extensions_server_name
#              -e tls.handshake.extensions_supported_group -e tls.handshake.extensions_ec_point_format
#              -e tls.handshake.extensions_alpn_str -e tls.handshake.sig_hash_alg
#              -e tls.handshake.extensions.supported_version -e frame.time
#              -R "ssl.handshake.type==1 or ssl.handshake.type==2" -2 
# 
#              input CSV format: SrcIP;DstIP;TCP SrcPort;TCP DstPort;UDP SrcPort; UDP DstPort;Proto;Type;Ver;
#                 Ciphersuite;List of extensions;SNI;Supported Groups;EC;ALPN;Signature Algorithms;Supported Versions;Time
#
#             full CSV ouput: SrcIP;DstIP;SrcPort;DstPort;Proto;SNI;OrgName;TLS Version;Client CipherSuite;Client Extensions;
#                 Client Supported Groups;EC_fmt;ALPN;Signature Algorithms;Client SuppVers;
#                 JA3hash;JA4;JA4_r;Application Name;Type;Server CipherSuite;Server Extensions;Server SuppVers;
#                 JA3S hash; JA4S hash;JA4S_r hash;filename;Version
#    -short:  prints a simple output: srcIP;dstIP;srcPort;dstPort;SNI;Orgname;JA3 hash;JA4 hash; Application Name; Type; JA3s hash;
#                 JA4s hash;filename;Version
#
#    ad-list.txt: it expects this text file where each line contains a domain name of an advertisement or analytics server
#                 ad-list entries are compiled from public lists of ads servers, e.g.,
#
#    <resolution_file>: an optional file that maps TLS handshakes to applications based on the source port number
#                       CSV format is expected: <local port>,<process name>
#                       if the file is available, process names will be assigned to TLS communication with the given local port 
#
#   <whois.csv>: an optional file that maps destination IP address (from the Client Hello) to WHOIS organization names
#                if an IP address is not found in the file, empty string is assigned
#                required CSV format: <dst IPv4 address>,<whois org name>
#
#           the search in WHOIS db can be very slow
#

# Date: 27/2/2024
# (c) Petr Matousek, Brno University of Technology, matousp@fit.vutbr.cz
# Created as a part of the FETA project (2022-2025)
#
# Changes: 05/20245 - extended format: AppName, Version, Type
#                  - ad-list.txt added: SNI found in the list are marked as advertisements (type = "A")
#                  - resolution.csv input added with mapping client's ports to application names
#                  - format of CSV values changed (AppName and Type at the end of to the client part)
#                  - whois.csv option added
#                  - WHOIS Organization added to the output
#          06/2024 - Version name chaned to TLS Version because of duplicated column names (app version, TLS version)
#          08/2024 - Full ALPN added, signature algorithms and supported versions sent to the output CSV
#          09/2024 - Check and ignores a duplicated Server Hello
#
use strict;
use Getopt::Long;
use Digest::MD5 qw(md5 md5_hex md5_base64);
use Digest::SHA qw(sha256_hex);

#
# global vars
#
my ($delim) = ";";
my ($adlist) = "ad-list.txt";
my (%tls_db);    # a hash array of all processed TLS handshakes
my (%short_db);  # a hash array of unique entries of the short list
my (%adservers); # a hash array of advertisement servers
my (%res_db);    # a hash array of source ports mapped to process names
my (%whois_db);  # a hash array of destination IP addresses mapped to WHOIS orgnames

&Main;

#
# sub Main
#
sub Main {
    my ($filename,$resfile,$whoisfile,$FILE, $ADFILE,$RESFILE,$WHOISFILE);
    my ($short,$ad) = (0,0);     # short listing (default = 0), ad file added (default = 0)
    my ($AppName, $Version, $Type) = ("Unknown","0","0");
    my ($app_name, $app_type);
    my ($OrgName);
    my ($srcIP,$dstIP,$srcTCPort,$dstTCPort,$srcUDPort,$dstUDPort,$proto);
    my ($type,$version,$cipher_suite,$sni,$supported_groups,$extensions,$ec_format,$alpn,$full_alpn,$supported_versions,$sig,$time);
    my ($row,$key,$entry,$cipher_suite_dec,@cipher_sorted,@ext_sorted,@ver_sorted);
    my ($ja4_version, $ja4_protocol, $ja4_sni,$ja4_suites_no, $ja4_cipher_suite,$ja4_ext_no,$ja4_ext,$ja4_alpn,$ja4_sig);
    my ($srcPort, $dstPort);
    my ($lineno);
    my ($count);
    my ($ja3,$ja3s,$ja4,$ja4_r,$ja4s,$ja4s_r,$ja4_a,$ja4_b,$ja4_c);
    my (@groups, $sg, $i, @suites, @ext,$str,@alpn_list,@sup_versions);
    my (@GREASE_HEX) = ("0x0a0a","0x1a1a","0x2a2a","0x3a3a","0x4a4a","0x5a5a","0x6a6a","0x7a7a","0x8a8a","0x9a9a","0xaaaa","0xbaba","0xcaca","0xdada","0xeaea","0xfafa");
    my (@GREASE) = (2570,6682,10794,14906,19018,23130,27242,31354,35466,39578,43690,47802,51914,56026,60138,64250); #,65281);
    my (%TLS_MAPPER) = ('256' => "s1", '512' => "s2", '0x0300' => "s3", '0x0301' => "10", '0x0302' => "11", '0x0303' => "12", '0x0304' => "13");

    GetOptions("file=s" => \$filename, "short" => \$short, "app:s" => \$AppName, "ver:s" => \$Version, "type:s" => \$Type, "res:s" => \$resfile, "whois=s" => \$whoisfile); 
    if (!$filename){
	print "Format: $0 -f <input.csv> [-short] [-app AppName] [-ver Version] [-type <0|A|M>] [-res <resolution.csv>] [-whois <whois.csv>]\n";
	exit 1;
    }

    if (! ($Type =~ /[0AM]/)){
	print "Unknown flag '$Type' -- use 0 (normal traffic), M (malware) or A (analytics)\n";
	exit 1;
    }
    
    if (!open ($FILE,$filename)){
	print "Cannot open file '$filename'\n";
	exit 1;
    }

    if ($resfile){
	if (!open ($RESFILE,$resfile)){
	    print "Cannot open file '$resfile'\n";
	    exit 1;
	} else {
	    $lineno = 0;
	    while (<$RESFILE>){
		$lineno++;
		$row = $_;
		$row =~ s/\r//g;          # remove a DOS end of line
		if ($row =~ /(.+),(.+)/)  # expected format: "port,process_name"
		{
		    $res_db{$1} = $2;
		} else {
		    print "Unexpected input on line $lineno in file $resfile.\n";
		    exit 1;
		}
	    }
	}
    }

    if ($whoisfile){
	if (!open ($WHOISFILE,$whoisfile)){
	    print "Cannot open file '$whoisfile'\n";
	    exit 1;
	} else {
	    $lineno = 0;
	    while (<$WHOISFILE>){
		$lineno++;
		$row = $_;
		$row =~ s/\r//g;          # remove a DOS end of line
		if ($row =~ /(.+);(.+)/)  # expected file format: "IP address;owner description from WHOIS"
		{
		    $whois_db{$1} = $2;
		} else {
		    print "Unexpected input on line $lineno in file $whoisfile.\n";
		    exit 1;
		}
	    }
	}
    }

    if (open ($ADFILE,$adlist)){
	$ad = 1;
	while (<$ADFILE>){        # reading the adfile -> each line contains one domain name
	    $row = $_;
	    $row =~ s/\r//g;      # remove a DOS end of line
	    chop($row);
	    $adservers{$row}=1;   # add a new advertisment domain to the associative array
	}
    }

    # reads the CSV-formatted file which is an output of tshark preprocessing using the filter above
    while (<$FILE>){
	$row = $_;
	$app_name = $AppName;             # take application name from the input arg
	$app_type = $Type;
	chop($row);
        if ($row  =~ /(.+);(.+);(.*);(.*);(.*);(.*);(.+);(.+);(.+);(.+);(.+);(.*);(.*);(.*);(.*);(.*);(.*);(.*)/){
	    if ($1 eq "SrcIP"){           # skip the CSV header
		next;
	    }
	    $srcIP = $1;                  # read IP addresses, ports and protocol type (TCP/UDP)
	    $dstIP = $2;
	    $OrgName = "";
	    if ($whoisfile){              # if whois resolution file is available, resolve the dst IP address
		if ($whois_db{$dstIP}){       
		    $OrgName = $whois_db{$dstIP}; # resolve the dstIP using the WHOIS database
		}
	    }		
	    $srcTCPort = $3;
	    $dstTCPort = $4;
	    $srcUDPort = $5;
	    $dstUDPort = $6;
	    $proto = $7;
	    if ($proto == 6){            # TCP communication (TLS over TCP)
		$srcPort = $srcTCPort;
		$dstPort = $dstTCPort;
		$ja4_protocol = "t";
	    } else {                     # UDP communication (QUIC over UDP)
		$srcPort = $srcUDPort;
		$dstPort = $dstUDPort;
		$ja4_protocol = "q";
	    }	
	    if ($resfile){               # check if the local port can be mapped to an application
		if ($res_db{$srcPort}){
		    $app_type = 0;
		    $app_name = $res_db{$srcPort}; # assign the mapping from the external resolution file
#		    print "resolution for port $srcPort: app_name = $app_name\n";
		} 
	    }
	    $type = $8;                  # TLS handshake type (Client Hello = 1, Server Hello = 2)
	    @groups = split /\,/,$8;     # in case of the Server Hello, more types can be included into one packet
	    $type = $groups[0];          # only the first value is intereting 
	    $version = hex($9);
	    $cipher_suite = $10;         # A list of cipher suites
	    $ja4_cipher_suite = $10; 
	    $extensions = $11;	
	    $sni = $12;
	    if ($sni ne ""){             # set the SNI to "d" (domain) if SNI is non-empty or to "i" (IP) if empty
		$ja4_sni = "d";
		if ($ad && $adservers{$sni}){   # if a SNI is in the ad-list file, the TLS fingerprint is marked as "A" (ads)
		    $app_type = "A";      # change the type to "A"
		}
		else {
		    $app_type = $Type;    # take default value (from the argument)
		}
	    } else {
		$ja4_sni = "i";
	    }
	    $supported_groups = $13;
	    $ec_format = $14;
	    if ($15 eq ""){              # select the ALPN string (application layer protocol)
		$alpn = "00";                       # if empty, set the predefined value
		$full_alpn = "";                    # initialize the full ALPN string
	    } else {
		$full_alpn = $15;
		@alpn_list = split /\,/,$15;    # if non-empty, select the first value in the list
		$alpn = $alpn_list[0];
		if (length($alpn) > 2){         # if a string is too short, map it to two chars
		    my $first = substr $alpn,0,1;
		    my $last = substr $alpn,-1;
		    $alpn=$first.$last;
		}
	    }
	    $sig = $16;                             # a list of hash algorithms for JA4 signature (extension type 0x0d = 13)
	    $ja4_version = $17;                     # a list of supported versions (extension type 0x2b = 43)
	    $supported_versions = $17;              # keeps original value for the extended output CSV
	    $time = $18;
	    @suites = split /\,/,$cipher_suite;     # convert the cipher suites from hex to decimal format for JA3 hash
	    $cipher_suite_dec = "";
	    foreach $i (@suites){                   
		if ($cipher_suite_dec eq ""){
		    $cipher_suite_dec = hex($i);
		}
		else
		{
		    $cipher_suite_dec = $cipher_suite_dec."-".hex($i);
		}
	    }
	    $extensions =~ s/\,/\-/g;               # JA4 hash expects a list of extensions separated by '-'
	    foreach $i (@GREASE){                   # exclude GREASE values from the cipher_suites and extensions for JA3
		$cipher_suite_dec =~ s/$i-//g;
		$cipher_suite_dec =~ s/-$i//g;
		$extensions =~ s/$i-//g;
		$extensions =~ s/-$i//g;
	    }
	    foreach $i (@GREASE_HEX){               # exclude GREASE_HEX values from cipher_suites and supported_versions for JA4
		$ja4_cipher_suite =~ s/$i,//g;
		$ja4_cipher_suite =~ s/,$i//g;
		$ja4_version =~ s/$i,//g;
		$ja4_version =~ s/,$i//g;
	    }
	    @suites = split /\,/,$ja4_cipher_suite; # processing JA4 cipher suites
	    @cipher_sorted = sort @suites;          # sort the cipher suites for JA4 Client Hello
	    $ja4_cipher_suite = join(",",@cipher_sorted);
	    $ja4_cipher_suite =~ s/(0x)//g;         # remove 0x prefix in hex numbers
	    if ($ja4_version eq ""){                # if extension supported_versions is not present
		$i = "0x".sprintf("%04x",$version); # use the handshake TLS version converted to hex
	    } else {
		@sup_versions = split /\,/,$ja4_version;
		@ver_sorted = sort @sup_versions;   # select the max SSL version from the supported groups
		$i = $ver_sorted[$#ver_sorted];     # the highest value of the sorted list has the last index
	    }
	    if ($TLS_MAPPER{$i}){                   # map the TLS value to the JA4 string
		$ja4_version = $TLS_MAPPER{$i}; 
	    } else {                                # current TLS version not found in the list
		$ja4_version = "00";
	    }
	    $ja4_suites_no = $ja4_cipher_suite =~ tr/,//;      # count the number of cipher suites separated by ","
	    $ja4_suites_no = sprintf("%02d",++$ja4_suites_no); # two digit number is expected
	    @ext = split /\-/,$extensions;          # process a list of extensions for JA4 fingerprint
	    if ($type == 1){                                   # Client Hello -> sorted list required
		@ext_sorted = sort {$a <=> $b} @ext;
	    } else {                                           # Server Hello -> the order of extensions preserved
		@ext_sorted = @ext;
	    }
	    $i = @ext_sorted;                                  # the number of extensions
	    $ja4_ext_no = sprintf("%02d",$i);  
	    $ja4_ext = "";
	    foreach $i (@ext_sorted){
		$str = sprintf("%0.4x",$i);                    # convert decimal extension to hexadecimal
		if  ($str eq "0000" or $str eq "0010"){        # skip SNI or ALPN extensions
		    next;
		} elsif ($ja4_ext eq ""){
		    $ja4_ext = $str;
		} else {
		    $ja4_ext = $ja4_ext.",".$str;
		}
	    }
	    $sig =~ s/(0x)//g;
	    @groups = split /\,/,$supported_groups; # process supported groups for JA3 fingerprint
	    $sg="";
	    foreach $i (@groups){                   # convert supported groups from hex to dec
		if ($sg eq ""){ 
		    $sg = hex($i);
		} else {
		    $sg=$sg."-".hex($i);
		}
	    }
	    foreach $i (@GREASE){                   # exclude GREASE values from the supported groups
		$sg =~ s/$i-//g;                
		$sg =~ s/-$i//g; 
	    }
	    #
	    # compute JA3, JA4, JA3S and JA4S hashes
	    #
	    if ($type == 1){          # Client Hello fingerprints JA3 and JA4
		$key = $srcIP.":".$dstIP.":".$srcPort;  # compute a hash key for the Client Hello for %tls_db

		                                        # compute the JA3 client fingerprint
		$ja3 = md5_hex($version.",".$cipher_suite_dec.",".$extensions.",".$sg.",".$ec_format);
		                                        # compute the JA4 client fingerpring
		$ja4_a=$ja4_protocol.$ja4_version.$ja4_sni.$ja4_suites_no.$ja4_ext_no.$alpn;
		$ja4_b = substr(sha256_hex($ja4_cipher_suite),0,12);
		$ja4_c = substr(sha256_hex($ja4_ext."_".$sig),0,12);
		$ja4_r = $ja4_a."_".$ja4_cipher_suite."_".$ja4_ext."_".$sig;  # raw format
		$ja4 = $ja4_a."_".$ja4_b."_".$ja4_c;                          # hash format
		
		# create a new entry
		if ($short){
		    $entry = $srcIP.$delim.$dstIP.$delim.$srcPort.$delim.$dstPort.$delim.$sni.$delim.$OrgName.$delim.$ja3.$delim.$ja4.$delim.$app_name.$delim.$app_type;
		} else {
		    $entry = $srcIP.$delim.$dstIP.$delim.$srcPort.$delim.$dstPort.$delim.$proto.$delim.$sni.$delim.$OrgName.$delim.$version.$delim.$cipher_suite_dec.$delim.$extensions.$delim.$supported_groups.$delim.$ec_format.$delim.$full_alpn.$delim.$sig.$delim.$supported_versions.$delim.$ja3.$delim.$ja4.$delim.$ja4_r.$delim.$app_name.$delim.$app_type;
		}
		# insert a new entry into the TLS hash array
		$tls_db{$key} = $entry;    
	    }
	    else {                    # Server Hello fingerprints JA3s and JA4s
		                                        # compute the JA3 server fingerprint
		$ja3s = md5_hex($version.",".$cipher_suite_dec.",".$extensions);
		                                        # compute the JA4 server fingerprint
		$ja4_a = $ja4_protocol.$ja4_version.$ja4_ext_no.$alpn;
		$ja4_b = $ja4_cipher_suite;
		$ja4_c = substr(sha256_hex($ja4_ext),0,12);
		$ja4s_r = $ja4_a."_".$ja4_b."_".$ja4_ext;                 # raw format
		$ja4s = $ja4_a."_".$ja4_b."_".$ja4_c;                     # hash format
		$key = $dstIP.":".$srcIP.":".$dstPort;  # compute a hash key for the Server Hello for %tls_db
		if ($tls_db{$key}){         # if a Client Hello exists in the db
		    $entry = $tls_db{$key}; # add data from the Server Hello to the entry
		    $count = ($entry =~ tr/;//);      # check the number of delimiters in the entry
#		    print "Count ($count, $short): \"$entry\"\n";
		    if ($short){
			if ($count > 9){ # 9 - max delimiters for the preprocessed client hello (for raw output)	
			    next;
			}
			$tls_db{$key} = $entry.$delim.$ja3s.$delim.$ja4s.$delim.$filename.$delim.$Version;
		    } else {
			if ($count > 19){ # 19 - max delimiters for the preprocessed client hello (for raw output)
			    next;         # process only client entries without the server part (skip duplicated server Hello)
			}
			$tls_db{$key} = $entry.$delim.$cipher_suite_dec.$delim.$extensions.$delim.$supported_versions.$delim.$ja3s.$delim.$ja4s.$delim.$ja4s_r.$delim.$filename.$delim.$Version;
		    }
		}
	    } # end if  (Server Hello)
	} # end if (row )
    } # end of input reading (while loop)
    #
    # print the output in CSV format 
    #
    if ($short){   # short output
	print "SrcIP".$delim."DstIP".$delim."SrcPort".$delim."DstPort".$delim."SNI".$delim."OrgName".$delim."JA3hash".$delim."JA4hash".$delim."AppName".$delim."Type".$delim."JA3Shash".$delim."JA4Shash".$delim."Filename".$delim."Version"."\n";
    } else {       # the full output with raw fingerprint format
	print "SrcIP".$delim."DstIP".$delim."SrcPort".$delim."DstPort".$delim."Proto".$delim."SNI".$delim."OrgName".$delim."TLSVersion".$delim."ClientCipherSuite".$delim."ClientExtensions".$delim."ClientSupportedGroups".$delim."EC_fmt".$delim."ALPN".$delim."SignatureAlgorithms".$delim."ClientSupportedVersions".$delim."JA3hash".$delim."JA4hash".$delim."JA4_raw".$delim."AppName".$delim."Type".$delim."ServerCipherSuite".$delim."ServerExtensions".$delim."ServerSupportedVersions".$delim."JA3Shash".$delim."JA4Shash".$delim."JA4S_raw".$delim."Filename".$delim."Version"."\n";
    }
    foreach $key (sort keys %tls_db){
	print $tls_db{$key}."\n";
    }
} # end main
