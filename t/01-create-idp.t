use Test::More;
use Net::SAML2;

my $xml = <<XML;
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<EntityDescriptor entityID="http://sso.dev.venda.com/opensso" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
    <IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>
MIICQDCCAakCBEeNB0swDQYJKoZIhvcNAQEEBQAwZzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNh
bGlmb3JuaWExFDASBgNVBAcTC1NhbnRhIENsYXJhMQwwCgYDVQQKEwNTdW4xEDAOBgNVBAsTB09w
ZW5TU08xDTALBgNVBAMTBHRlc3QwHhcNMDgwMTE1MTkxOTM5WhcNMTgwMTEyMTkxOTM5WjBnMQsw
CQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEUMBIGA1UEBxMLU2FudGEgQ2xhcmExDDAK
BgNVBAoTA1N1bjEQMA4GA1UECxMHT3BlblNTTzENMAsGA1UEAxMEdGVzdDCBnzANBgkqhkiG9w0B
AQEFAAOBjQAwgYkCgYEArSQc/U75GB2AtKhbGS5piiLkmJzqEsp64rDxbMJ+xDrye0EN/q1U5Of+
RkDsaN/igkAvV1cuXEgTL6RlafFPcUX7QxDhZBhsYF9pbwtMzi4A4su9hnxIhURebGEmxKW9qJNY
Js0Vo5+IgjxuEWnjnnVgHTs1+mq5QYTA7E6ZyL8CAwEAATANBgkqhkiG9w0BAQQFAAOBgQB3Pw/U
QzPKTPTYi9upbFXlrAKMwtFf2OW4yvGWWvlcwcNSZJmTJ8ARvVYOMEVNbsT4OFcfu2/PeYoAdiDA
cGy/F2Zuj8XJJpuQRSE6PtQqBuDEHjjmOQJ0rV/r8mO1ZCtHRhpZ5zYRjhRC9eCbjx9VrFax0JDC
/FfwWigmrW0Y0Q==
                    </ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </KeyDescriptor>
        <ArtifactResolutionService index="0" isDefault="true" Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="http://sso.dev.venda.com/opensso/ArtifactResolver/metaAlias/idp"/>
        <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://sso.dev.venda.com/opensso/IDPSloRedirect/metaAlias/idp" ResponseLocation="http://sso.dev.venda.com/opensso/IDPSloRedirect/metaAlias/idp"/>
        <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://sso.dev.venda.com/opensso/IDPSloPOST/metaAlias/idp" ResponseLocation="http://sso.dev.venda.com/opensso/IDPSloPOST/metaAlias/idp"/>
        <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="http://sso.dev.venda.com/opensso/IDPSloSoap/metaAlias/idp"/>
        <ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://sso.dev.venda.com/opensso/IDPMniRedirect/metaAlias/idp" ResponseLocation="http://sso.dev.venda.com/opensso/IDPMniRedirect/metaAlias/idp"/>
        <ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://sso.dev.venda.com/opensso/IDPMniPOST/metaAlias/idp" ResponseLocation="http://sso.dev.venda.com/opensso/IDPMniPOST/metaAlias/idp"/>
        <ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="http://sso.dev.venda.com/opensso/IDPMniSoap/metaAlias/idp"/>
        <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
        <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName</NameIDFormat>
        <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos</NameIDFormat>
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName</NameIDFormat>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://sso.dev.venda.com/opensso/SSORedirect/metaAlias/idp"/>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://sso.dev.venda.com/opensso/SSOPOST/metaAlias/idp"/>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="http://sso.dev.venda.com/opensso/SSOSoap/metaAlias/idp"/>
        <NameIDMappingService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="http://sso.dev.venda.com/opensso/NIMSoap/metaAlias/idp"/>
        <AssertionIDRequestService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="http://localhost:43312/opensso/AIDReqSoap/IDPRole/metaAlias/idp"/>
        <AssertionIDRequestService Binding="urn:oasis:names:tc:SAML:2.0:bindings:URI" Location="http://localhost:43312/opensso/AIDReqUri/IDPRole/metaAlias/idp"/>
    </IDPSSODescriptor>
</EntityDescriptor>
XML

my $idp = Net::SAML2::IdP->new($xml);
ok($idp);

my $redirect_uri = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
my $soap_uri     = 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP';

ok($idp->sso_url($redirect_uri));
ok($idp->slo_url($redirect_uri));
ok($idp->art_url($soap_uri));

done_testing;
