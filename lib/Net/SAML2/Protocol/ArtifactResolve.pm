package Net::SAML2::Protocol::ArtifactResolve;
use Moose;
use MooseX::Types::Moose qw/ Str /;
use MooseX::Types::URI qw/ Uri /;

with 'Net::SAML2::Role::Templater',
     'Net::SAML2::Role::ProtocolMessage';

=head1 NAME

Net::SAML2::Protocol::ArtifactResolve - ArtifactResolve protocol class.

=head1 SYNOPSIS

  my $resolver = Net::SAML2::Binding::ArtifactResolve->new(
    issuer => 'http://localhost:3000',
  );

  my $response = $resolver->resolve(params->{SAMLart});

=head1 METHODS

=cut

=head2 new( ... )

Constructor. Returns an instance of the ArtifactResolve request for
the given issuer and artifact.

Arguments:

 * issuer - the issuing SP's identity URI
 * artifact - the artifact to be resolved
 * destination - the IdP's identity URI

=cut

has 'artifact'    => (isa => Str, is => 'ro', required => 1);
has 'issuer'      => (isa => Uri, is => 'ro', required => 1, coerce => 1);
has 'destination' => (isa => Uri, is => 'ro', required => 1, coerce => 1);


=head2 as_xml

Returns the ArtifactResolve request as XML.

=cut

sub as_xml {
        my ($self) = @_;

        my $template = <<'EOXML';
<samlp:ArtifactResolve xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"   
   ID="<?= $_[0]->id ?>"
   IssueInstant="<?= $_[0]->issue_instant ?>"
   Destination="<?= $_[0]->destination ?>" 
   ProviderName="My SP's human readable name."
   Version="2.0">
   <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><?= $_[0]->issuer ?></saml:Issuer>
   <samlp:Artifact><?= $_[0]->artifact ?></samlp:Artifact>
</samlp:ArtifactResolve>
EOXML

	return $self->template($template);
}

1;
