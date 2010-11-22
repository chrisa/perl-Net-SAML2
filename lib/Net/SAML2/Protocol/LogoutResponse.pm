package Net::SAML2::Protocol::LogoutResponse;
use Moose;
use MooseX::Types::Moose qw/ Str /;
use MooseX::Types::URI qw/ Uri /;

with 'Net::SAML2::Role::Templater',
     'Net::SAML2::Role::ProtocolMessage';

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

has 'issuer'	  => (isa => Uri, is => 'ro', required => 1, coerce => 1);
has 'destination' => (isa => Uri, is => 'ro', required => 1, coerce => 1);
has 'status'	  => (isa => Str, is => 'ro', required => 1);
has 'response_to' => (isa => Str, is => 'ro', required => 1);

=head2 new_from_xml

Create a LogoutResponse object from the given XML.

=cut

sub new_from_xml {
	my ($class, %args) = @_;
     
	my $xpath = XML::XPath->new( xml => $args{xml} );
	$xpath->set_namespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
	$xpath->set_namespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');

	my $self = $class->new(
		id	    => $xpath->findvalue('/samlp:LogoutResponse/@ID')->value,
		response_to => $xpath->findvalue('/samlp:LogoutResponse/@InResponseTo')->value,
		destination => $xpath->findvalue('/samlp:LogoutResponse/@Destination')->value,
		session     => $xpath->findvalue('/samlp:LogoutResponse/samlp:SessionIndex')->value,
		issuer	    => $xpath->findvalue('/samlp:LogoutResponse/saml:Issuer')->value,
		status	    => $xpath->findvalue('/samlp:LogoutResponse/samlp:Status/samlp:StatusCode/@Value')->value,
	);

	return $self;
}

=head2 as_xml()

Returns the LogoutResponse as XML.

=cut

sub as_xml {
	my ($self) = @_;

	my $template =<<'EOXML';
<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
    ID="<?= $_[0]->id ?>" 
    Version="2.0" 
    IssueInstant="<?= $_[0]->issue_instant ?>"
    Destination="<?= $_[0]->destination ?>" 
    InResponseTo="<?= $_[0]->response_to ?>">
         <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><?= $_[0]->issuer ?></saml:Issuer>
         <samlp:Status xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
             <samlp:StatusCode xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Value="<?= $_[0]->status ?>"/>
         </samlp:Status>
</samlp:LogoutResponse>
EOXML

	return $self->template($template);
}

1;
