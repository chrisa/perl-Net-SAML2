package Net::SAML2::Protocol::AuthnRequest;
use Moose;
use MooseX::Types::Moose qw /Str /;
use MooseX::Types::URI qw/ Uri /;

with 'Net::SAML2::Role::Templater',
     'Net::SAML2::Role::ProtocolMessage';

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

=head2 new( ... )

Constructor. Creates an instance of the AuthnRequest object. 

Arguments:

 * issuer - the SP's identity URI
 * destination - the IdP's identity URI

=cut

has 'issuer'	  => (isa => Uri, is => 'ro', required => 1, coerce => 1);
has 'destination' => (isa => Uri, is => 'ro', required => 1, coerce => 1);

=head2 as_xml()

Returns the AuthnRequest as XML.

=cut

sub as_xml {
        my ($self) = @_;

        my $template =<<'EOXML';
<sp:AuthnRequest xmlns:sp="urn:oasis:names:tc:SAML:2.0:protocol"
                 Destination="<?= $_[0]->destination ?>" 
                 ID="<?= $_[0]->id ?>"
                 IssueInstant="<?= $_[0]->issue_instant ?>" 
                 ProviderName="My SP's human readable name."
                 Version="2.0">
  <sa:Issuer xmlns:sa="urn:oasis:names:tc:SAML:2.0:assertion"><?= $_[0]->issuer ?></sa:Issuer>
  <sp:NameIDPolicy AllowCreate="1"
                   Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"/>
</sp:AuthnRequest>
EOXML

	return $self->template($template);
}

1;
        
