#!/usr/bin/perl
#-------------------------------------------------------------------------
#
# generate_ca_header.pl
#	  Convert one or more trust anchor PEM files into a C header holding
#	  their DER bytes.
#
# The build never fetches a trust anchor over the network. A build that
# downloads its own trust anchor can be redirected by anyone controlling DNS,
# a proxy, or the build container. The committed PEM is the source of truth.
#
# More than one input is accepted so a CA rotation can ship a build that
# accepts both the outgoing and the incoming root during the transition.
#
# Usage:
#	  generate_ca_header.pl --output out.h input.pem [input2.pem ...]
#
# Portions Copyright (c) 1996-2025, PostgreSQL Global Development Group
#
#-------------------------------------------------------------------------

use strict;
use warnings FATAL => 'all';
use MIME::Base64 qw(decode_base64);

my $output;
my $pin_output;
my @inputs;

while (my $arg = shift @ARGV)
{
	if ($arg eq '--output')
	{
		$output = shift @ARGV or die "--output requires an argument\n";
	}
	elsif ($arg eq '--pin-output')
	{
		# Only used for dev CA builds. The production pin is hand maintained in
		# ca_pin.c precisely so that replacing the committed PEM alone does not
		# silently regenerate a matching digest.
		$pin_output = shift @ARGV or die "--pin-output requires an argument\n";
	}
	else
	{
		push @inputs, $arg;
	}
}

die "usage: generate_ca_header.pl --output out.h [--pin-output pin.h] input.pem [...]\n"
  unless defined $output && @inputs;

# Decode every CERTIFICATE block in a PEM file to DER.
sub pem_to_der
{
	my ($path) = @_;
	open my $fh, '<', $path or die "could not open $path: $!\n";
	local $/ = undef;
	my $text = <$fh>;
	close $fh;

	my @ders;
	while ($text =~ /-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/gs)
	{
		my $b64 = $1;
		$b64 =~ s/\s+//g;
		push @ders, decode_base64($b64);
	}
	die "no CERTIFICATE block found in $path\n" unless @ders;
	return @ders;
}

my @anchors;
foreach my $in (@inputs)
{
	foreach my $der (pem_to_der($in))
	{
		push @anchors, { der => $der, src => $in };
	}
}

open my $out, '>', $output or die "could not write $output: $!\n";

print $out <<"EOH";
/*-------------------------------------------------------------------------
 *
 * appscode_root_ca.h
 *	  Embedded license trust anchors, generated at build time.
 *
 * GENERATED FILE, DO NOT EDIT.
 * Regenerate with src/backend/license/generate_ca_header.pl.
 *
 * These bytes are the only trust anchors the license verifier will ever
 * accept. The X509_STORE is created empty and only these are added, so
 * SSL_CERT_FILE, SSL_CERT_DIR, and the OpenSSL default paths have no effect
 * on license verification.
 *
 *-------------------------------------------------------------------------
 */
#ifndef APPSCODE_ROOT_CA_H
#define APPSCODE_ROOT_CA_H

EOH

my $n = 0;
foreach my $a (@anchors)
{
	my @bytes = unpack 'C*', $a->{der};
	printf $out "/* from %s, %d bytes DER */\n", $a->{src}, scalar(@bytes);
	printf $out "static const unsigned char appscode_trust_anchor_%d[] = {\n", $n;

	my @line;
	foreach my $b (@bytes)
	{
		push @line, sprintf('0x%02x', $b);
		if (@line == 12)
		{
			print $out "\t", join(', ', @line), ",\n";
			@line = ();
		}
	}
	print $out "\t", join(', ', @line), "\n" if @line;
	print $out "};\n\n";
	$n++;
}

print $out "typedef struct AppscodeTrustAnchor\n";
print $out "{\n";
print $out "\tconst unsigned char *der;\n";
print $out "\tunsigned int len;\n";
print $out "} AppscodeTrustAnchor;\n\n";

print $out "static const AppscodeTrustAnchor appscode_trust_anchors[] = {\n";
for my $i (0 .. $n - 1)
{
	printf $out "\t{ appscode_trust_anchor_%d, (unsigned int) sizeof(appscode_trust_anchor_%d) },\n",
	  $i, $i;
}
print $out "};\n\n";
printf $out "#define APPSCODE_TRUST_ANCHOR_COUNT %d\n\n", $n;
print $out "#endif\t\t\t\t\t\t\t/* APPSCODE_ROOT_CA_H */\n";

close $out;

printf STDERR "generate_ca_header.pl: wrote %s with %d trust anchor(s)\n",
  $output, $n;

#
# Optional SPKI pin header, for dev CA builds only.
#
# Extracting the SubjectPublicKeyInfo without an ASN.1 library means walking
# the certificate structure, so shell out to openssl instead. This path is only
# reached in test builds, where openssl is already required to create the dev
# CA in the first place.
#
if (defined $pin_output)
{
	open my $pin, '>', $pin_output or die "could not write $pin_output: $!\n";

	print $pin <<'EOP';
/*
 * dev_ca_pin.h
 *	  GENERATED FILE, DO NOT EDIT. Development CA only.
 *
 * A release build must never include this. The production pin is hand
 * maintained in ca_pin.c.
 */
const unsigned char appscode_ca_spki_pins[][32] = {
EOP

	foreach my $in (@inputs)
	{
		my $hex = `openssl x509 -in "$in" -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -r 2>/dev/null`;
		die "could not compute SPKI digest for $in\n" unless $hex;
		$hex =~ s/\s.*$//s;
		die "unexpected digest '$hex' for $in\n" unless $hex =~ /^[0-9a-f]{64}$/;

		print $pin "\t{\n";
		my @b = ($hex =~ /(..)/g);
		for my $row (0 .. 3)
		{
			print $pin "\t\t",
			  join(', ', map { "0x$_" } @b[ $row * 8 .. $row * 8 + 7 ]), ",\n";
		}
		print $pin "\t},\n";
	}

	print $pin "};\n\n";
	print $pin "const int\tappscode_ca_spki_pin_count =\n";
	print $pin "\t(int) (sizeof(appscode_ca_spki_pins) / sizeof(appscode_ca_spki_pins[0]));\n";
	close $pin;

	printf STDERR "generate_ca_header.pl: wrote %s (development pins)\n",
	  $pin_output;
}
