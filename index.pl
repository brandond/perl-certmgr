#!/usr/bin/perl

use strict;
use Switch;
use CGI;
use File::Temp qw(tempfile);
use HTML::Template;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::X509 qw(FORMAT_ASN1 FORMAT_PEM);
use Crypt::OpenSSL::PKCS10;
use Crypt::OpenSSL::PKCS12;
use Encode qw(encode decode);
use Data::Dumper;

my $cgi = CGI->new();
$cgi->charset('utf-8');

my $form_update_cert = HTML::Template->new(filename => 'tmpl/form_update_cert.html', die_on_bad_params => 0, associate => $cgi);
my $form_copy_cert =   HTML::Template->new(filename => 'tmpl/form_copy_cert.html',   die_on_bad_params => 0, associate => $cgi);
my $form_make_cert =   HTML::Template->new(filename => 'tmpl/form_make_cert.html',   die_on_bad_params => 0, associate => $cgi);
my $form_new =         HTML::Template->new(filename => 'tmpl/form_new.html',         die_on_bad_params => 0, associate => $cgi);

# Force SSL
unless ($cgi->https()){
  my $url = $cgi->url();
  $url =~ s/http:/https:/;
  print $cgi->redirect($url);
  exit();
}

# Switch output based on action
switch ($cgi->param('action')){
  case 'update'   { print_form_update_cert() }
  case 'copycert' { print_form_copy_cert() }
  case 'create'   { print_form_make_cert() }
  else            { print_form_new() }
}

# output pkcs12 cert replacement form
sub print_form_update_cert {
  if ($cgi->param('pfx') && $cgi->param('passphrase')){
    if (my ($cert, $key) = extract_pkcs12()){
      # this will fill fields directly into the global CGI object for the template
      fill_form_update_cert($key);
    } else {
      # if it fails, extract_pkcs12 will set the error message before returning
      return print_form_new();
    }
  } elsif ($cgi->param('privatekey')){
    # if create_pkcs12 fails, will set the error message before returning
    if (my ($pfx, $name) = create_pkcs12()){
      return send_pkcs12($pfx, $name);
    }
  }

  print $cgi->header(-type => 'text/html');
  print $form_update_cert->output();
}

# output cert copy / field editor form
sub print_form_copy_cert {
  if ($cgi->param('pfx')){
    if (my ($cert, $key) = extract_pkcs12()){
      if ($cert){
        # if we got a pkcs12 archive containing an existing cert, fill fields 
        # directly into the global CGI object for the template
        fill_form_copy_cert($cert, $key);
      } else {
        # Got an existing private key, but no cert. Start a blank CSR with this key.
        $cgi->param('privatekey', $key);
        return print_form_make_cert();
      }
    } else {
      # if extract_pkcs12 fails, it will set the error message before returning
      return print_form_new();
    }
  } elsif ($cgi->param('submit_csr')){
    # if create_pkcs10 fails, it will set the error message before returning
    if (my ($req, $name) = create_pkcs10()){
      return send_pkcs10($req, $name);
    }
  }
  print $cgi->header(-type => 'text/html');
  print $form_copy_cert->output();
}

# output new blank certificate request form
sub print_form_make_cert {
  if ($cgi->param('submit_csr')){
    # if create_pkcs10 fails, it will set the error message before returning
    if (my ($req, $name) = create_pkcs10()){
      return send_pkcs10($req, $name);
    }
  } elsif ($cgi->param('submit_key')){
    # if create_pkcs8 fails, will set the error message before returning
    if (my ($key, $name) = create_pkcs8()){
      return send_pkcs8($key, $name);
    }
  }
  fill_form_make_cert();
  print $cgi->header(-type => 'text/html');
  print $form_make_cert->output();
}

# output initial archive upload form
sub print_form_new {
  print $cgi->header(-type => 'text/html');
  print $form_new->output();
}

# Send PKCS8 (RSA private key). first param is actual Base64-encoded key.
sub send_pkcs8 {
  my $pkcs8 = shift;
  my $name = shift;
  $pkcs8 =~ s/\n/\r\n/g;
  print $cgi->header(-type => 'application/pkcs8', -content_disposition => 'attachment; filename="'.$name.'.key"');
  print $pkcs8;
}

# Send PKCS10 (certificate signing request). first param is actual Base64-encoded CSR.
sub send_pkcs10 {
  my $pkcs10 = shift;
  my $name = shift;
  $pkcs10 =~ s/\n/\r\n/g;
  print $cgi->header(-type => 'application/pkcs10', -content_disposition => 'attachment; filename="'.$name.'.csr"');
  print $pkcs10;
}

# Send PKCS12 archive. First param is filename of archive temp file.
sub send_pkcs12 {
  my $file = shift;
  my $name = shift;
  local $/ = undef;
  print $cgi->header(-type => 'application/x-pkcs12', -content_disposition => 'attachment; filename="'.$name.'.pfx"');
  my $FH;
  open($FH, "<$file");
  print <$FH>;
  close($FH);
  unlink($file);
}

# Extract cert and key from archive
sub extract_pkcs12 {
  my $name = $cgi->param('pfx');
  my $file = $cgi->tmpFileName($name);
  my $pass = $cgi->param('passphrase');

  if (is_pkcs8($file)){
    local $/ = undef;
    my $FH;
    my $key;
    open($FH, "<$file");
    my $key_str = <$FH>;
    close($FH);
    eval {
      $key = Crypt::OpenSSL::RSA->new_private_key($key_str, $pass)->get_private_key_string();
    };
    if ($@){
      print STDERR "extract_pkcs12: error $@\n";
      $cgi->param('error', "Invalid PKCS8 archive or archive passphrase");
      return;
    }
    return (undef, $key);
  }

  my $pkcs12;
  eval {
    $pkcs12 = Crypt::OpenSSL::PKCS12->new_from_file($file);
    $pkcs12->mac_ok($pass) 
  };
  if ($@){
    print STDERR "extract_pkcs12: error $@\n";
    $cgi->param('error', "Invalid PKCS12 archive or archive passphrase");
    return;
  }

  my $cert = $pkcs12->certificate($pass);
  my $key  = $pkcs12->private_key($pass);
  return ($cert, $key);
}


# Create a new RSA keypair
sub create_rsa {
  my $length = shift || 2048;
  my $rsa;
  eval {
    $rsa = Crypt::OpenSSL::RSA->generate_key($length);
  };
  if ($@){
    print STDERR "generate_key: error $@\n";
    $cgi->param('error', "Unable to generate new RSA keypair");
    return;
  }
  return $rsa->get_private_key_string();
}


# Create archive, given cert, key, and passphrase
sub create_pkcs12 {
  my $pass = $cgi->param('passphrase');
  my $type = $cgi->param('cert_type');
  my ($temp, $cert_cn) = eval {
    my $cert;
    my $key = $cgi->param('privatekey');
    if($type eq 'cert_file'){
      my $file = $cgi->tmpFileName($cgi->param('cert_file'));
      my $format = get_cert_format($file);
      $cert = Crypt::OpenSSL::X509->new_from_file($file, $format);
    } else {
      $cert = Crypt::OpenSSL::X509->new_from_string($cgi->param('cert_text'));
    }
    my $cert_cn   = $cert->subject_name()->get_entry_by_type('CN')->value();
    my $cert_nb   = $cert->notBefore();
    $cert_nb =~ s/(\w+ \d+) (\d+:\d+:\d+) (\d+) (\w+)/$2 $1 $3 ($4)/;
    my ($fh, $temp) = tempfile();
    close($fh);
    Crypt::OpenSSL::PKCS12->create($cert->as_string(), $key, $pass, $temp, "$cert_cn - issued $cert_nb");
    return ($temp, $cert_cn);
  };
  if ($@){
    print STDERR "create_pkcs12: error $@\n";
    if ($@ =~ m/Error creating PKCS#12 structure/){
      $cgi->param('error', 'Certificate/Private Key modulus mismatch<BR>Was this certificate requested using a different private key?');
    } else {
      $cgi->param('error', "Failed to create archive: $@");
    }
    return;
  }
  return ($temp, $cert_cn);
}

# Create CSR given private key. Params are taken from form input.
sub create_pkcs10 {
  my $key = Crypt::OpenSSL::RSA->new_private_key($cgi->param('privatekey'));
  my $req = Crypt::OpenSSL::PKCS10->new_from_rsa($key);
  
  # build subject
  my $subject = '/'.join ('/', map { 
    if ($cgi->param($_)){
      # emailAddress can be retrieved by short name but not set...
      my $key = $_ eq 'E' ? 'emailAddress' : $_;
      my $val = $cgi->param($_);
      $val =~ s/([\\\/=])/\\$1/g;
      "$key=$val";
    } else {
      ();
    } 
  } qw(CN OU O ST L C E));
  eval {
    $req->set_subject($subject);
  };
  if ($@){
    print STDERR "create_pkcs10: error setting subject to $subject: $@\n";
    $cgi->param('error', "Error setting certificate subject: $@");
    return;
  }

  # fill raw types
  foreach my $oid qw(2.5.29.14 1.3.6.1.4.1.311.20.2) {
    if ('hash' eq lc($cgi->param($oid))){
      $req->add_ext(Crypt::OpenSSL::PKCS10::NID_subject_key_identifier, 'hash');
    } elsif (my $val = substr($cgi->param($oid), 1)){
      eval {
        $req->add_custom_ext_raw($oid, pack('H*', $val));
      };
      if ($@){
        print STDERR "Error setting extension $oid to $val: $@\n";
        $cgi->param('error', "Error setting extension $oid");
        return;
      }
    }
  }

  # fill special types
  my %nids = ('2.5.29.15'              => Crypt::OpenSSL::PKCS10::NID_key_usage,
              '2.5.29.17'              => Crypt::OpenSSL::PKCS10::NID_subject_alt_name,
              '2.5.29.37'              => Crypt::OpenSSL::PKCS10::NID_ext_key_usage,
              '2.16.840.1.113730.1.13' => Crypt::OpenSSL::PKCS10::NID_netscape_comment);
  while ( my ($oid, $nid) = each(%nids) ){
    if (my $val = join(', ', $cgi->param($oid))){
      eval {
        $req->add_ext($nid, $val);
      };
      if ($@){ 
        print STDERR "Error setting extension $oid to $val\n";
        $cgi->param('error', "Error setting extension $oid");
        return;
      }
    }
  }
  eval {
    $req->add_ext_final();
    $req->sign();
  };
  if ($@){
    $cgi->param('error', "Error finalizing certificate configuration: $@");
    return;
  }

  return ($req->get_pem_req(), $cgi->param('CN'));
}

sub create_pkcs8 {
  my $key = Crypt::OpenSSL::RSA->new_private_key($cgi->param('privatekey'));
  return ($key->get_private_key_string($cgi->param('passphrase')), $cgi->param('CN'));
}

sub fill_form_update_cert {
  my $key = shift;
  # persist base64-encoded private key
  $cgi->param('privatekey', $key);
  $cgi->param('cert_file', 1);
}

sub fill_form_copy_cert {
  my $cert = Crypt::OpenSSL::X509->new_from_string(shift);
  my $key = shift;
  
  # persist base64-encoded private key
  $cgi->param('privatekey', $key);

  # Extract issuer
  $cgi->param('issuer', $cert->issuer);

  # Extract subject from cert
  my %subject = map { 
    $_->type() => { string => $_->value() } 
  } @{$cert->subject_name()->entries()};
  
  # Extract extended attributes from cert
  my %extents = map {
    my $ext = $cert->extension($_);
    $ext->object()->oid() => { raw => $ext->value(), string => $ext->to_string() };
  } 0..$cert->num_extensions()-1;

  # Merge hashes
  my %certinfo = (%subject, %extents);
  use Data::Dumper;
  print STDERR Dumper \%certinfo;

  # Extract text fields for potential modification
  foreach my $field qw(CN OU O ST L C E 2.5.29.15 2.5.29.17 2.5.29.37 2.16.840.1.113730.1.13){
    $cgi->param($field, $certinfo{$field}{'string'});
  }
 
  # Extract raw fields for direct copy
  foreach my $field qw(2.5.29.14){
    $cgi->param($field, $certinfo{$field}{'raw'});
  }
 
  # populate dropdown list of certificate templates
  $cgi->param('1.3.6.1.4.1.311.20.2', get_templates($certinfo{'1.3.6.1.4.1.311.20.2'}{'raw'}));

}

sub fill_form_make_cert {
  # ensure private key
  if (! $cgi->param('privatekey')){
    $cgi->param('privatekey', create_rsa());
  }

  # populate default key usage and extended key usage
  $cgi->param('2.5.29.14', 'hash');
  $cgi->param('2.5.29.15', 'Digital Signature, Key Encipherment');
  $cgi->param('2.5.29.37', 'TLS Web Server Authentication');

  # Populate default location information
  $cgi->param('OU', 'Org Unit');
  $cgi->param('O', 'Organization');
  $cgi->param('L', 'City');
  $cgi->param('ST', 'State');
  $cgi->param('C', 'US'); 

  # populate dropdown list of certificate templates
  $cgi->param('1.3.6.1.4.1.311.20.2', get_templates());
}

sub get_templates {
  my $current = shift();
  my $selected;
  my @templates = ( {'NAME' => 'Secure IP Web Server 10 year 2048', 
                     'ASN'  => '#1E36005300650063007500720065004900500057006500620053006500720076006500720031003000790065006100720032003000340038'},
                    {'NAME' => 'Secure IP Web Server 10 year', 
                     'ASN'  => '#1E2E00530065006300750072006500490050005700650062005300650072007600650072003100300079006500610072'},
                    {'NAME' => 'Web Server', 
                     'ASN'  => '#1E12005700650062005300650072007600650072'},
                    {'NAME' => 'External Client Cert',
                     'ASN'  => '#1E2400450078007400650072006E0061006C0043006C00690065006E00740043006500720074'}, );
  for (my $i = 0; $i < @templates; $i++){
    if ($templates[$i]->{'ASN'} eq $current){
      $templates[$i]->{'SELECTED'} = 1;
      $selected = 1;
    }
  }
  if ($current && !$selected){
    my $name = decode('UCS-2BE', pack('H*', substr($current, 5))); 
    push(@templates, {NAME => $name, ASN => $current, SELECTED => 1} );
  }
  return \@templates;
}

sub get_cert_format {
  my $file = shift;
  my $ret;
  my $FH;
  open($FH, "<$file") or die "Failed to open certificate temp file: $!";
  my $head = readline($FH);
  if ($head =~ m/BEGIN CERTIFICATE/){
    $ret = FORMAT_PEM;
  } else {
    $ret = FORMAT_ASN1;
  }
  close($FH);
  return $ret;
}

sub is_pkcs8 {
  my $file = shift;
  my $ret;
  my $FH;
  open($FH, "<$file") or die "Failed to open pkcs8/12 temp file: $!";
  my $head = readline($FH);
  if ($head =~ m/BEGIN.*PRIVATE KEY/){
    $ret = 1
  } else {
    $ret = 0;
  }
  close($FH);
  return $ret;
}
