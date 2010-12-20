package Net::SAML2::Role::ProtocolMessage;
use Moose::Role;
use MooseX::Types::Moose qw/ Str /;
use DateTime::Format::XSD;
use Crypt::OpenSSL::Random;

=head1 NAME

Net::SAML2::Role::Templater - defaults for Protocol classes

=head1 DESCRIPTION

Provides default ID and timestamp arguments for Protocol classes.

=cut

has 'id'            => (isa => Str, is => 'ro', required => 1);
has 'issue_instant' => (isa => Str, is => 'ro', required => 1);

around 'BUILDARGS' => sub {
        my $orig = shift;
        my $class = shift;      
        my %args = @_;

        # random ID for this message
        $args{id} ||= unpack 'H*', Crypt::OpenSSL::Random::random_pseudo_bytes(16);

        # IssueInstant in UTC
        my $dt = DateTime->now( time_zone => 'UTC' );
        $args{issue_instant} ||= $dt->strftime('%FT%TZ');
        
        return \%args;
};

1;
