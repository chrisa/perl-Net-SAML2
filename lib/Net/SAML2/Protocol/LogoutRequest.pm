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

=head2 new_from_xml

Create a LogoutRequest object from the given XML.

=cut

sub new_from_xml {
	my ($class, %args) = @_;
        my $self = bless {}, $class;

        my $xpath = XML::XPath->new( xml => $args{xml} );
        $xpath->set_namespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
	$xpath->set_namespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');

	$self->{id}          = $xpath->findvalue('/samlp:LogoutRequest/@ID')->value;
        $self->{session}     = $xpath->findvalue('/samlp:LogoutRequest/samlp:SessionIndex')->value;
        $self->{issuer}	     = $xpath->findvalue('/samlp:LogoutRequest/saml:Issuer')->value;
        $self->{nameid}	     = $xpath->findvalue('/samlp:LogoutRequest/saml:NameID')->value;
	$self->{destination} = $xpath->findvalue('/samlp:LogoutRequest/saml:NameID/@NameQualifier')->value;

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

=head2 id

Returns the ID of the parsed response.

=cut

sub id { 
	my ($self) = @_;
        return $self->{id};
}

=head2 session

Returns the Session attribute of the parsed response.

=cut

sub session { 
	my ($self) = @_;
        return $self->{session};
}

=head2 nameid

Returns the NameID attribute of the parsed response.

=cut

sub nameid {
	my ($self) = @_;
        return $self->{nameid};
}

=head2 issuer

Returns the Issuer URI  of the parsed response.

=cut

sub issuer {
	my ($self) = @_;
        return $self->{issuer};
}

=head2 destination

Returns the Destination URI of the parsed response.

=cut

sub destination {
	my ($self) = @_;
        return $self->{destination};
}

1;
