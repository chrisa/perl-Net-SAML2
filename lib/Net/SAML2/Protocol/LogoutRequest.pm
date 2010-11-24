package Net::SAML2::Protocol::LogoutRequest;
use Moose;
use MooseX::Types::Common::String qw/ NonEmptySimpleStr /;
use MooseX::Types::URI qw/ Uri /;

with 'Net::SAML2::Role::Templater',
     'Net::SAML2::Role::ProtocolMessage';

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

has 'session'	  => (isa => NonEmptySimpleStr, is => 'ro', required => 1);
has 'nameid'	  => (isa => NonEmptySimpleStr, is => 'ro', required => 1);
has 'issuer'	  => (isa => Uri, is => 'ro', required => 1, coerce => 1);
has 'destination' => (isa => Uri, is => 'ro', required => 1, coerce => 1);

=head2 new_from_xml

Create a LogoutRequest object from the given XML.

=cut

sub new_from_xml {
	my ($class, %args) = @_;

        my $xpath = XML::XPath->new( xml => $args{xml} );
        $xpath->set_namespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
	$xpath->set_namespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');

	my $self = $class->new(
		id          => $xpath->findvalue('/samlp:LogoutRequest/@ID')->value,
		session     => $xpath->findvalue('/samlp:LogoutRequest/samlp:SessionIndex')->value,
		issuer	    => $xpath->findvalue('/samlp:LogoutRequest/saml:Issuer')->value,
		nameid	    => $xpath->findvalue('/samlp:LogoutRequest/saml:NameID')->value,
		destination => $xpath->findvalue('/samlp:LogoutRequest/saml:NameID/@NameQualifier')->value,
	);

	return $self;
}

=head2 as_xml()

Returns the LogoutRequest as XML.

=cut

sub as_xml {
        my ($self) = @_;

	my $template = <<'EOXML';
<sp:LogoutRequest xmlns:sp="urn:oasis:names:tc:SAML:2.0:protocol"
	ID="<?= $_[0]->id ?>" IssueInstant="<?= $_[0]->issue_instant ?>"
	Version="2.0">
	<sa:Issuer xmlns:sa="urn:oasis:names:tc:SAML:2.0:assertion"><?= $_[0]->issuer ?></sa:Issuer>
	<sa:NameID xmlns:sa="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
		   NameQualifier="<?= $_[0]->destination ?>" 
                   SPNameQualifier="<?= $_[0]->issuer ?>"><?= $_[0]->nameid ?></sa:NameID>
	<sp:SessionIndex><?= $_[0]->session ?></sp:SessionIndex>
</sp:LogoutRequest>
EOXML

	return $self->template($template);
}

__PACKAGE__->meta->make_immutable;
