package Net::SAML2::Protocol::LogoutRequest;
use strict;
use warnings;

=head1 NAME

Net::SAML2::Protocol::LogoutRequest - the SAML2 LogoutRequest object

=head1 SYNOPSIS

  my $logout_req = Net::SAML2::Protocol::LogoutRequest->new(
    issuer      => $issuer,
    destination => $destination,
    nameid      => $nameid,
    session     => $session,
  );

=head1 METHODS

=head2 new( ... )

Constructor. Returns an instance of the LogoutRequest object.

Arguments:

 * session - the session to log out
 * nameid - the NameID of the user to log out
 * issuer - the SP's identity URI
 * destination -  the IdP's identity URI

=cut

sub new { 
        my ($class, %args) = @_;
        my $self = bless {}, $class;

        $self->{session}     = $args{session};
        $self->{nameid}      = $args{nameid};
        $self->{issuer}      = $args{issuer};
        $self->{destination} = $args{destination};

        return $self;
}

=head2 as_xml()

Returns the LogoutRequest as XML.

=cut

sub as_xml {
        my ($self) = @_;

        my $xml =<<"EOXML";
<sp:LogoutRequest xmlns:sp="urn:oasis:names:tc:SAML:2.0:protocol"
	ID="21B78E9C6C8ECF16F01E4A0F15AB2D46" IssueInstant="2010-04-28T21:36:11.230Z"
	Version="2.0">
	<sa:Issuer xmlns:sa="urn:oasis:names:tc:SAML:2.0:assertion">$self->{issuer}</sa:Issuer>
	<sa:NameID xmlns:sa="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
		   NameQualifier="$self->{destination}" 
                   SPNameQualifier="$self->{issuer}">$self->{nameid}</sa:NameID>
	<sp:SessionIndex>$self->{session}</sp:SessionIndex>
</sp:LogoutRequest>
EOXML

        return $xml;
}

1;
        
