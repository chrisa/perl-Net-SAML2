package Net::SAML2::SP;
use strict;
use warnings;

use Crypt::OpenSSL::X509;

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
