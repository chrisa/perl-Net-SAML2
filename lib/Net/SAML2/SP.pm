package Net::SAML2::SP;
use strict;
use warnings;

=head1 NAME

Net::SAML2::SP - SAML Service Provider object

=head1 SYNOPSIS

  my $sp = Net::SAML2::SP->new(
    id   => 'http://localhost:3000',
    url  => 'http://localhost:3000',
    cert => 'sign-nopw-cert.pem',
  );

=head1 METHODS

=cut

use Crypt::OpenSSL::X509;

=head2 new( ... )

Constructor. Create an SP object. 

Arguments:

 * url    - the base for all SP service URLs
 * id     - the SP's identity URI. 
 * cert   - path to the signing certificate
 * cacert - path to the CA certificate for verification

 * org_name         - the SP organisation name
 * org_display_name - the SP organisation display name
 * org_contact      - an SP contact email address

=cut

sub new { 
        my ($class, %args) = @_;
        my $self = bless {}, $class;

	$self->{cacert_path} = $args{cacert};
	$self->{cert_path}   = $args{cert};
	$self->{url}	     = $args{url};
	$self->{id}	     = $args{id};

	$self->{org_name}         = $args{org_name};
	$self->{org_display_name} = $args{org_display_name};
	$self->{org_contact}      = $args{org_contact};

        my $cert = Crypt::OpenSSL::X509->new_from_file($args{cert});
        $self->{cert} = $cert->as_string;
        $self->{cert} =~ s/-----[^-]*-----//gm;

        return $self;
}

=head2 authn_request($destination)

Returns an AuthnRequest object created by this SP, intended for the
given destination, which should be the identity URI of the IdP.

=cut

sub authn_request {
	my ($self, $destination) = @_;
	
	my $authnreq = Net::SAML2::Protocol::AuthnRequest->new(
		issueinstant => DateTime->now,
		issuer       => $self->{id},
		destination  => $destination,
	);
	
	return $authnreq;
}

=head2 logout_request($destination, $nameid, $session)

Returns a LogoutRequest object created by this SP, intended for the
given destination, which should be the identity URI of the IdP.

Also requires the nameid and session to be logged out. 

=cut

sub logout_request {
	my ($self, $destination, $nameid, $session) = @_;

	my $logout_req = Net::SAML2::Protocol::LogoutRequest->new(
                issuer      => $self->{id},
                destination => $destination,
                nameid      => $nameid,
                session     => $session,
        );

	return $logout_req;
}

=head2 logout_response($destination, $status, $response_to)

Returns a LogoutResponse object created by this SP, intended for the
given destination, which should be the identity URI of the IdP.

Also requires the status and the ID of the corresponding
LogoutRequest.

=cut

sub logout_response {
	my ($self, $destination, $status, $response_to) = @_;

	my $logout_req = Net::SAML2::Protocol::LogoutResponse->new(
                issuer      => $self->{id},
                destination => $destination,
		status      => $status,
		response_to => $response_to,
        );

	return $logout_req;
}

=head2 artifact_request($destination, $artifact)

Returns an ArtifactResolve request object created by this SP, intended
for the given destination, which should be the identity URI of the
IdP.

=cut

sub artifact_request {
	my ($self, $destination, $artifact) = @_;
	
	my $artifact_request = Net::SAML2::Protocol::ArtifactResolve->new(
		issuer	     => $self->{id},
		destination  => $destination,
		artifact     => $artifact,
		issueinstant => DateTime->now,
	);
	
	return $artifact_request;
}

=head2 redirect_binding

Returns a Redirect binding object for this SP, configured against the
given IDP.

=cut

sub redirect_binding {
	my ($self, $idp) = @_;
	
	my $redirect = Net::SAML2::Binding::Redirect->new(
		key => $self->{cert_path},
		url => $idp,
	);
	
	return $redirect;
}

=head2 soap_binding

Returns a SOAP binding object for this SP, with a destination of the
given URL and signing certificate.

XXX UA

=cut

sub soap_binding {
	my ($self, $ua, $idp_url, $idp_cert) = @_;

	my $soap = Net::SAML2::Binding::SOAP->new(
		ua       => $ua,
		key	 => $self->{cert_path},
		cert	 => $self->{cert_path},
		url	 => $idp_url,
		idp_cert => $idp_cert,
	);
	
	return $soap;
}

=head2 post_binding

Returns a POST binding object for this SP.

=cut

sub post_binding {
	my ($self) = @_;
	
        my $post = Net::SAML2::Binding::POST->new(
		cacert => $self->{cacert_path},
	);
	
	return $post;
}

=head2 metadata

Returns the metadata XML document for this SP.

=cut

sub metadata {
        my ($self) = @_;

        return <<"METADATA";
<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="$self->{id}">
  <md:SPSSODescriptor AuthnRequestsSigned="1" WantAssertionsSigned="1" errorURL="$self->{url}/error" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>
$self->{cert}
          </ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="$self->{url}/slo-soap"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="$self->{url}/consumer-post" index="1" isDefault="true"/>
  </md:SPSSODescriptor>
  <md:Organization>
    <md:OrganizationName xml:lang="en">$self->{org_name}</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="en">$self->{org_display_name}</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="en">$self->{url}/</md:OrganizationURL>
  </md:Organization>
  <md:ContactPerson contactType="other">
    <md:Company>$self->{org_display_name}</md:Company>
    <md:EmailAddress>$self->{org_contact}</md:EmailAddress>
  </md:ContactPerson>
</md:EntityDescriptor>
METADATA
}

1;
