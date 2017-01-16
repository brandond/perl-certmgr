#!/usr/bin/perl

use strict;
use Encode qw/encode decode/;

my $ucs2 = encode('UCS-2BE', $ARGV[0]);
my $bmpString = sprintf '#1E%02X%s', length($ucs2), unpack('H*', $ucs2);
my $origStr = decode('UCS-2BE', pack('H*', substr($bmpString, 5)));

print "$bmpString\n";
print "$origStr\n";



