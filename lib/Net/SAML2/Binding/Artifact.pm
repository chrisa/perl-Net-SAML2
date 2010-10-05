package Net::SAML2::Binding::Artifact;
use strict;
use warnings;

=head1 NAME

Net::SAML2::Binding::Artifact - SOAP Artifact binding for SAML2

=head1 SYNOPSIS

  my $resolver = Net::SAML2::Binding::Artifact->new(
    url    => $art_url,
    key    => 'sign-private.pem',
    cert   => 'sign-certonly.pem',
    issuer => 'http://localhost:3000',
  );

  my $response = $resolver->resolve(params->{SAMLart});

=head1 METHODS

=cut

use XML::Sig;
use LWP::UserAgent;
use HTTP::Request::Common;

=head2 new( ... )

Constructor. Returns an instance of the Artifact binding configured
for the given SP issuer and IdP resolver service url. 

Arguments:

 * url - the resolver service URL
 * key - path to the signing key
 * cert - path to the signing certificate
 * issuer - the issuing SP's identity URI

=cut

sub new {
        my ($class, %args) = @_;
        my $self = bless {}, $class;

        $self->{url} = $args{url};
        $self->{key} = $args{key};
        $self->{cert} = $args{cert};
        $self->{issuer} = $args{issuer};

        return $self;
}

=head2 resolve($artifact)

Resolve the given artifact, which should be an opaque SAML2 artifact id. 

Returns the Artifact, or dies if there was an error.

=cut

sub resolve {
        my ($self, $artifact) = @_;

        my $saml_req = <<XML;
 <samlp:ArtifactResolve
   xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"   
   ID="_cce4ee769ed970b501d680f697989d14"
   IssueInstant="2010-09-18T17:33:01Z"
   Destination="foo" 
   ProviderName="My SP's human readable name."
   Version="2.0">
   <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">$self->{issuer}</saml:Issuer>
   <samlp:Artifact>$artifact</samlp:Artifact>
 </samlp:ArtifactResolve>
XML

        my $sig = XML::Sig->new({ x509 => 1, key => $self->{key}, cert => $self->{cert} });
        my $signed_saml_req = $sig->sign($saml_req);

        my $ret = $sig->verify($signed_saml_req);
        die "failed to sign" unless $ret;

        my $soap_req = <<"SOAP";
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP-ENV:Body>
$saml_req
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

        my $sig_verify = XML::Sig->new({ x509 => 1 });
        $ret = $sig_verify->verify($res->content);
        die "bad artifact response" unless $ret;
        
        return $res->content;
}

1;
