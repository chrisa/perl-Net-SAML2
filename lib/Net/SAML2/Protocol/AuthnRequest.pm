package Net::SAML2::Protocol::AuthnRequest;
use strict;
use warnings;

=head1 NAME

Net::SAML2::Protocol::AuthnRequest - SAML2 AuthnRequest object

=head1 SYNOPSIS

  my $authnreq = Net::SAML2::Protocol::AuthnRequest->new(
    issueinstant => DateTime->now,
    issuer       => $self->{id},
    destination  => $destination,
  );

=head1 METHODS

=cut

use DateTime::Format::XSD;

=head2 new( ... )

Constructor. Creates an instance of the AuthnRequest object. 

Arguments:

 * issueinstant - a DateTime for "now"
 * issuer - the SP's identity URI
 * destination - the IdP's identity URI

=cut

sub new { 
        my ($class, %args) = @_;
        my $self = bless {}, $class;

	$self->{issueinstant} = $args{issueinstant};
        $self->{issuer}       = $args{issuer};
        $self->{destination}  = $args{destination};

        return $self;
}

=head2 as_xml()

Returns the AuthnRequest as XML.

=cut

sub as_xml {
        my ($self) = @_;

	my $issueinstant = DateTime::Format::XSD->format_datetime(
		$self->{issueinstant}
	);
	
        my $xml =<<"EOXML";
<?xml version="1.0"?>
<sp:AuthnRequest xmlns:sp="urn:oasis:names:tc:SAML:2.0:protocol"
                 Destination="$self->{destination}" 
                 ID="N3k95Hg41WCHdwc9mqXynLPhB"
                 IssueInstant="$issueinstant" 
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
        
