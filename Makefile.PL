use strict;
use warnings;

use ExtUtils::MakeMaker;

WriteMakefile(
  NAME         => 'Mojolicious::Plugin::OAuth2Accounts',
  VERSION_FROM => 'lib/Mojolicious/Plugin/OAuth2Accounts.pm',
  AUTHOR       => 'A Good Programmer <nospam@cpan.org>',
  PREREQ_PM    => {'Mojolicious' => '6.12'},
  test         => {TESTS => 't/*.t'}
);
