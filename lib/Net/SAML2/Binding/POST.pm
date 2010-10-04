package Net::SAML2::Binding::POST;
use strict;
use warnings;

use XML::Sig;
use MIME::Base64 qw/ decode_base64 /;

sub new {
        my ($class, %args) = @_;
        my $self = bless {}, $class;
        return $self;
}

sub handle_response {
        my ($self, $response) = @_;
        my $xml = decode_base64($response);
        my $x = XML::Sig->new({ x509 => 1 });
        my $ret = $x->verify($xml);
        return $ret;
}
        
1;
