package Net::SAML2::Binding::POST;
use strict;
use warnings;

=head1 NAME

Net::SAML2::Binding::POST - HTTP POST binding for SAML2

=head1 SYNOPSIS

  my $post = Net::SAML2::Binding::POST->new;
  my $ret = $post->handle_response(
    $saml_response
  );

=head1 METHODS

=cut

use XML::Sig;
use MIME::Base64 qw/ decode_base64 /;

=head2 new()

Constructor. Returns an instance of the POST binding. 

No arguments.

=cut

sub new {
        my ($class, %args) = @_;
        my $self = bless {}, $class;
        return $self;
}

=head2 handle_response($response)

Decodes and verifies the response provided, which should be the raw
Base64-encoded response, from the SAMLResponse CGI parameter. 

=cut

sub handle_response {
        my ($self, $response) = @_;
        my $xml = decode_base64($response);
        my $x = XML::Sig->new({ x509 => 1 });
        my $ret = $x->verify($xml);
        return $ret;
}
        
1;
