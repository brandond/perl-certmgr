#!/usr/bin/perl

use strict;
use Switch;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::X509;
use Crypt::OpenSSL::PKCS12;
use Data::Dumper;

my $file = $ARGV[0];
my $pass = $ARGV[1];

my $pkcs12 = Crypt::OpenSSL::PKCS12->new_from_file($file);

#eval { $pkcs12->mac_ok($pass) };
#if ($@){
#  die "Invalid passphrase for $file";
#}

my $cert = Crypt::OpenSSL::X509->new_from_string($pkcs12->certificate($pass));

my %subject = map { $_->type() => $_->value() } @{$cert->subject_name()->entries()};
my %extents = map {
  my $ext = $cert->extension($_);
  $ext->object()->oid() => { raw => $ext->value(), string => $ext->to_string(), name => $ext->object()->name() };
} 0..$cert->num_extensions()-1;

my %info = (%subject, %extents);
print Dumper \%info;
