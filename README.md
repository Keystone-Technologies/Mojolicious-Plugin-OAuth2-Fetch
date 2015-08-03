# test.pl
use Mojolicious::Lite;

use lib '../Mojolicious-Plugin-OAuth2-Fetch/lib';

my $config = plugin 'Config';

plugin "OAuth2::Fetch";

get '/' => sub {
  my $c = shift;
  return unless $c->oauth2->connected;
} => 'home';

app->start;

__DATA__

@@ home.html.ep
ID: <%= $c->oauth2->id %><br />
Name: <%= $c->oauth2->me->{first_name} %>

# test.conf
{
  oauth2 => {
    mocked => {
      key => 42,
    },
  },
}
