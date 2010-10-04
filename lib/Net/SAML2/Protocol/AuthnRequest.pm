package Net::SAML2::Protocol::AuthnRequest;
use strict;
use warnings;

sub new { 
        my ($class, %args) = @_;
        my $self = bless {}, $class;

        $self->{issuer}      = $args{issuer};
        $self->{destination} = $args{destination};

        return $self;
}

sub as_xml {
        my ($self) = @_;

        my $xml =<<"EOXML";
<?xml version="1.0"?>
<sp:AuthnRequest xmlns:sp="urn:oasis:names:tc:SAML:2.0:protocol"
                 Destination="$self->{destination}" 
                 ID="N3k95Hg41WCHdwc9mqXynLPhB"
                 IssueInstant="2010-09-16T02:02:21Z" 
                 ProviderName="My SP's human readable name."
                 Version="2.0">
  <sa:Issuer xmlns:sa="urn:oasis:names:tc:SAML:2.0:assertion">$self->{issuer}</sa:Issuer>
  <sp:NameIDPolicy AllowCreate="1"
                   Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"/>
</sp:AuthnRequest>
EOXML

        return $xml;
}

1;
        
