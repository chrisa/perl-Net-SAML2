package Net::SAML2::Binding::Redirect;
use strict;
use warnings;

=head1 NAME

Net::SAML2::Binding::Redirect

=head1 SYNOPSIS

  my $redirect = Net::SAML2::Binding::Redirect->new(
    key => 'sign-nopw-cert.pem',
    url => $sso_url,
  );

  my $url = $redirect->sign_request($authnreq);

  # or
 
  my $ret = $post->handle_response(
    $saml_response
  );

=head1 METHODS

=cut

use MIME::Base64 qw/ encode_base64 decode_base64 /;
use IO::Compress::RawDeflate qw/ rawdeflate /;
use IO::Uncompress::RawInflate qw/ rawinflate /;
use URI;
use URI::QueryParam;
use Crypt::OpenSSL::RSA;
use File::Slurp qw/ read_file /;

=head2 new( ... )

Constructor. Creates an instance of the Redirect binding. 

Arguments:

 * key - the signing key
 * url - the IdP's SSO service url for the Redirect binding

=cut

sub new {
        my ($class, %args) = @_;
        my $self = bless {}, $class;

        $self->{key} = $args{key};
        $self->{url} = $args{url};

        return $self;
}

=head2 sign_request($request, $relaystate)

Signs the given request, and returns the URL to which the user's
browser should be redirected.

Accepts an optional RelayState parameter, a string which will be
returned to the requestor when the user returns from the
authentication process with the IdP.

=cut

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

=head2 handle_response($response)

Decode a Redirect binding URL. 

Should also verify the signature on the response. 

=cut

sub handle_response {
        my ($self, $response) = @_;
        my $deflated = decode_base64($response);

        my $output = '';
        rawinflate \$deflated => \$output;
        
        # Should verify the response

        return $output;
}

1;
        
