package Net::SAML2::Binding::SOAP;
use strict;
use warnings;

=head1 NAME

Net::SAML2::Binding::Artifact - SOAP binding for SAML2

=head1 SYNOPSIS

  my $soap = Net::SAML2::Binding::SOAP->new(
    url => $idp_url,
    key => $key,
    cert => $cert,
    idp_cert => $idp_cert,
  );

  my $response = $soap->request($req);

=head1 METHODS

=cut

use XML::Sig;
use LWP::UserAgent;
use HTTP::Request::Common;

=head2 new( ... )

Constructor. Returns an instance of the SOAP binding configured for
the given IdP service url.

Arguments:

 * url - the service URL
 * key - the key to sign with
 * cert - the corresponding certificate
 * idp_cert - the idp's signing certificate

=cut

sub new {
        my ($class, %args) = @_;
        my $self = bless {}, $class;

        $self->{url}  = $args{url};
        $self->{key}  = $args{key};
        $self->{cert} = $args{cert};
        $self->{idp_cert} = $args{idp_cert};

        return $self;
}

=head2 request($req)

Submit the request to the IdP's service.

Returns the Response, or dies if there was an error.

=cut

sub request {
        my ($self, $request) = @_;

	# sign the request
        my $sig = XML::Sig->new({ 
		x509 => 1,
		key  => $self->{key},
		cert => $self->{cert}
	});
        my $signed_req = $sig->sign($request);

	# test verify
        my $ret = $sig->verify($signed_req);
        die "failed to sign" unless $ret;

        my $soap_req = <<"SOAP";
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP-ENV:Body>
$signed_req
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
SOAP

        my $soap_action = 'http://www.oasis-open.org/committees/security';

        my $req = POST $self->{url};
        $req->header('SOAPAction' => $soap_action);
        $req->header('Content-Type' => 'text/xml');
        $req->header('Content-Length' => length $soap_req);
        $req->content($soap_req);

        my $ua = LWP::UserAgent->new;
        my $res = $ua->request($req);

        my $sig_verify = XML::Sig->new({ x509 => 1, cert_text => $self->{idp_cert} });
        $ret = $sig_verify->verify($res->content);
        die "bad SOAP response" unless $ret;
        
        return $res->content;
}

1;
