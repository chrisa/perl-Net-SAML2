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

 * url  - the base for all SP service URLs
 * id   - the SP's identity URI. 
 * cert - path to the signing certificate

=cut

sub new { 
        my ($class, %args) = @_;
        my $self = bless {}, $class;

        $self->{url} = $args{url};
	$self->{id}  = $args{id};

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

Returns an AuthnRequest object created by this SP, intended for the
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
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="$self->{url}/sls-redirect" ResponseLocation="$self->{url}/sls-redirect-response"/>
    <md:ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="$self->{url}/manage-redirect" ResponseLocation="$self->{url}/manage-redirect-response"/>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="$self->{url}/consumer-post" index="2"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="$self->{url}/consumer-artifact" index="1"/>
  </md:SPSSODescriptor>
  <md:Organization>
    <md:OrganizationName xml:lang="en">Saml2Test</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="en">Saml2Test app</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="en">$self->{url}/</md:OrganizationURL>
  </md:Organization>
  <md:ContactPerson contactType="other">
    <md:Company>Saml2Test</md:Company>
  </md:ContactPerson>
</md:EntityDescriptor>
METADATA
}

1;
