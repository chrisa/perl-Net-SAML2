package Net::SAML2;
use strict;
use warnings;

require 5.008_001;

our $VERSION = '0.01_01';
$VERSION = eval $VERSION;

=head1 NAME

Net::SAML2 - SAML bindings and protocol implementation

=head1 SYNOPSIS

=cut

# entities
use Net::SAML2::IdP;
use Net::SAML2::SP;

# bindings
use Net::SAML2::Binding::Redirect;
use Net::SAML2::Binding::Artifact;
use Net::SAML2::Binding::POST;

# protocol
use Net::SAML2::Protocol::AuthnRequest;
use Net::SAML2::Protocol::LogoutRequest;
use Net::SAML2::Protocol::Assertion;

=pod

=head1 AUTHOR

Chris Andrews <chrisandrews@venda.com>

=head1 COPYRIGHT

The following copyright notice applies to all the files provided in
this distribution, including binary files, unless explicitly noted
otherwise.

Copyright 2010 Venda Ltd

=head1 LICENCE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;
