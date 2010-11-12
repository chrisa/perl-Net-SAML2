package Net::SAML2::Protocol::LogoutResponse;
use strict;
use warnings;

=head1 NAME

Net::SAML2::Protocol::LogoutResponse - the SAML2 LogoutResponse object

=head1 SYNOPSIS

  my $logout_req = Net::SAML2::Protocol::LogoutResponse->new(
    issuer      => $issuer,
    destination => $destination,
    status      => $status,
    response_to => $response_to,
  );

=head1 METHODS

=head2 new( ... )

Constructor. Returns an instance of the LogoutResponse object.

Arguments:

 * issuer - the SP's identity URI
 * destination -  the IdP's identity URI
 * status - the response status
 * response_to - the request ID we're responding to

=cut

sub new { 
        my ($class, %args) = @_;
        my $self = bless {}, $class;

        $self->{issuer}      = $args{issuer};
        $self->{destination} = $args{destination};
        $self->{status}	     = $args{status};
        $self->{response_to} = $args{response_to};

        return $self;
}

=head2 new_from_xml

Create a LogoutResponse object from the given XML.

=cut

sub new_from_xml {
	my ($class, %args) = @_;
	my $self = bless {}, $class;
     
	my $xpath = XML::XPath->new( xml => $args{xml} );
	$xpath->set_namespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
	$xpath->set_namespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');

	$self->{id}	     = $xpath->findvalue('/samlp:LogoutResponse/@ID')->value;
	$self->{response_to} = $xpath->findvalue('/samlp:LogoutResponse/@InResponseTo')->value;
	$self->{destination} = $xpath->findvalue('/samlp:LogoutResponse/@Destination')->value;
	$self->{session}     = $xpath->findvalue('/samlp:LogoutResponse/samlp:SessionIndex')->value;
	$self->{issuer}	     = $xpath->findvalue('/samlp:LogoutResponse/saml:Issuer')->value;
	$self->{status}	     = $xpath->findvalue('/samlp:LogoutResponse/samlp:Status/samlp:StatusCode/@Value')->value;

	return $self;
}

=head2 as_xml()

Returns the LogoutResponse as XML.

=cut

sub as_xml {
	my ($self) = @_;

	my $xml =<<"EOXML";
<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
    ID="sba02cbf4142978d48fa339164d4bb6f20f49b761" 
    Version="2.0" 
    IssueInstant="2010-09-17T16:07:53Z"
    Destination="$self->{destination}" 
    InResponseTo="$self->{response_to}">
         <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">$self->{issuer}</saml:Issuer>
         <samlp:Status xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
             <samlp:StatusCode xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Value="$self->{status}"/>
         </samlp:Status>
</samlp:LogoutResponse>
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

=head2 response_to

Returns the InResponseTo attribute of the parsed response.

=cut

sub response_to {
	my ($self) = @_;
        return $self->{response_to};
}

=head2 issuer

Returns the issuer URI of the parsed response.

=cut

sub issuer {
	my ($self) = @_;
        return $self->{issuer};
}

=head2 destination

Returns the destination URI of the parsed response.

=cut

sub destination {
	my ($self) = @_;
        return $self->{destination};
}

=head2 status

Returns the status URI of the parsed response.

=cut

sub status {
	my ($self) = @_;
        return $self->{status};
}

1;
