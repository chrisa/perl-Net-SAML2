package Net::SAML2::Role::Templater;
use Moose::Role;
use Text::MicroTemplate qw/ build_mt /;

=head1 NAME

Net::SAML2::Role::Templater - simple templater routine for Protocol classes

=head1 DESCRIPTION

Template-processor role for Protocol classes. 

=head1 METHODS

=head2 template($template)

Evaluates the given template using $self as the context.

=cut

sub template {
	my ($self, $template) = @_;
	my $renderer = build_mt($template);
	my $xml = $renderer->($self)->as_string;
	return $xml;
}

1;
