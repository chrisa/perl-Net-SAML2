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
use XML::XPath;
use LWP::UserAgent;
use HTTP::Request::Common;

=head2 new( ... )

Constructor. Returns an instance of the SOAP binding configured for
the given IdP service url.

Arguments:

 * ua - (optionally) a LWP::UserAgent-compatible UA
 * url - the service URL
 * key - the key to sign with
 * cert - the corresponding certificate
 * idp_cert - the idp's signing certificate

=cut

sub new {
        my ($class, %args) = @_;
        my $self = bless {}, $class;

        $self->{ua}	  = $args{ua};
        $self->{url}	  = $args{url};
        $self->{key}	  = $args{key};
        $self->{cert}	  = $args{cert};
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

        my $ua = $self->{ua} || LWP::UserAgent->new;
        my $res = $ua->request($req);

	return $self->handle_response($res->content);
}

=head2 handle_response( $response )

Handle a response from a remote system on the SOAP binding.

Accepts a string containing the complete SOAP response.

=cut

sub handle_response {
	my ($self, $response) = @_;

	# verify the response
        my $sig_verify = XML::Sig->new({ x509 => 1, cert_text => $self->{idp_cert} });
        my $ret = $sig_verify->verify($response);
        die "bad SOAP response" unless $ret;

	# parse the SOAP response and return the payload
	my $parser = XML::XPath->new( xml => $response );
	$parser->set_namespace('soap-env', 'http://schemas.xmlsoap.org/soap/envelope/');
	$parser->set_namespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
	
	my $saml = $parser->findnodes_as_string('/soap-env:Envelope/soap-env:Body/*');
	return $saml;
}

=head2 handle_request( $request )

Handle a request from a remote system on the SOAP binding. 

Accepts a string containing the complete SOAP request.

=cut

sub handle_request {
	my ($self, $request) = @_;

	my $parser = XML::XPath->new( xml => $request );
	$parser->set_namespace('soap-env', 'http://schemas.xmlsoap.org/soap/envelope/');
	$parser->set_namespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');

	my $saml = $parser->findnodes_as_string('/soap-env:Envelope/soap-env:Body/*');

	if (defined $saml) {
		my $sig_verify = XML::Sig->new({ x509 => 1, cert_text => $self->{idp_cert} });
		my $ret = $sig_verify->verify($saml);
		return unless $ret;

		my $subject = $sig_verify->signer_cert->subject;
		return ($subject, $saml);
	}

	return;
}

=head2 create_response( $message )

Signs and SOAP-wraps the given message.

=cut

sub create_response {
	my ($self, $message) = @_;

	# sign the response
        my $sig = XML::Sig->new({ 
		x509 => 1,
		key  => $self->{key},
		cert => $self->{cert}
	});
        my $signed_res = $sig->sign($message);
	
	# test verify
        my $ret = $sig->verify($signed_res);
        die "failed to sign" unless $ret;

        my $soap_res = <<"SOAP";
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP-ENV:Body>
$signed_res
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
SOAP
	return $soap_res;
}

1;
