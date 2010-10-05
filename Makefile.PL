use inc::Module::Install;

name 'Net-SAML2';
all_from 'lib/Net/SAML2.pm';

requires 'XML::Sig';
requires 'Crypt::OpenSSL::RSA';
requires 'Crypt::OpenSSL::X509';
requires 'IO::Compress::RawDeflate';
requires 'IO::Uncompress::RawInflate';
requires 'File::Slurp';
requires 'URI';
requires 'MIME::Base64';
requires 'LWP::UserAgent';
requires 'XML::XPath';

resources
     license     => "http://dev.perl.org/licenses",
     bugtracker  => "http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-SAML2",
     repository  => "http://github.com/chrisa/perl-Net-SAML2";

WriteAll;
