package Net::SAML2::Binding::Redirect;
use strict;
use warnings;

use MIME::Base64 qw/ encode_base64 decode_base64 /;
use IO::Compress::RawDeflate qw/ rawdeflate /;
use IO::Uncompress::RawInflate qw/ rawinflate /;
use URI;
use URI::QueryParam;
use Crypt::OpenSSL::RSA;
use File::Slurp qw/ read_file /;

sub new {
        my ($class, %args) = @_;
        my $self = bless {}, $class;

        $self->{key} = $args{key};
        $self->{url} = $args{url};

        return $self;
}

sub sign_request {
        my ($self, $request, $relaystate) = @_;
        
        my $output = '';
        rawdeflate \$request => \$output;
        my $req = encode_base64($output, '');

        my $u = URI->new($self->{url});
        $u->query_param('SAMLRequest', $req);
        $u->query_param('RelayState', $relaystate) if defined $relaystate;
        $u->query_param('SigAlg', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1');

        my $key_string = read_file($self->{key});
        my $rsa_priv = Crypt::OpenSSL::RSA->new_private_key($key_string);

        my $to_sign = $u->query;
        my $sig = encode_base64($rsa_priv->sign($to_sign), '');
        $u->query_param('Signature', $sig);

        my $url = $u->as_string;
        return $url;
}

sub handle_response {
        my ($self, $response) = @_;
        my $deflated = decode_base64($response);

        my $output = '';
        rawinflate \$deflated => \$output;
        
        return $output;
}

1;
        
