package Mojolicious::Plugin::OAuth2Accounts;
use Mojo::Base 'Mojolicious::Plugin';

our $VERSION = '0.01';

has providers => sub {
  return {
    mocked => {
      args => {
        scope => 'user_about_me email',
      },
      fetch => '/mocked/me?access_token=%token%',
      map => {
        error => '/err/0',
        id => '/i',
        email => '/e',
        first_name => '/f',
        last_name => '/l',
      },
    },
    facebook => {
      args => {
        scope => 'user_about_me email',
      },
      fetch => 'https://graph.facebook.com/v2.3/me?access_token=%token%',
      map => {
        error => '/error/message',
        id => '/id',
        email => '/email',
        first_name => '/first_name',
        last_name => '/last_name',
      },
    },
  }
};

sub register {
  my ($self, $app, $config) = @_;

  my $oauth2_config = {};
  my $providers = $self->providers;

  foreach my $provider (keys %{$config->{providers}}) {
    if (exists $providers->{$provider}) {
      foreach my $key (keys %{$config->{providers}->{$provider}}) {
        $providers->{$provider}->{$key} = $config->{providers}->{$provider}->{$key};
      }
    }
    else {
      $providers->{$provider} = $config->{providers}->{$provider};
    }
  }

  $self->providers($providers);

  $app->plugin("OAuth2" => { fix_get_token => 1, %{$config->{providers}} });

  $app->routes->get('/logout' => sub {
    my $c = shift;
    my $token = $c->session('token') || {};
    delete $c->session->{$_} foreach keys %{$c->session};
    $token->{$_} = {} foreach keys %$token;
    $c->session(token => $token);
    $c->redirect_to($config->{on_logout});
  });

  $app->routes->get("/mocked/me" => sub {
    my $c = shift;
    my $access_token = $c->param('access_token');
    warn $access_token;
    return $c->render(json => {err => ['Invalid access token']}) unless $access_token eq 'fake_token';
    $c->render(json => { i => 123, f => 'a', l => 'a', e => 'a@a.com' });
  });

  $app->routes->get("/connect/:provider" => sub {
    my $c = shift;
    my $provider = $c->param('provider');
    my $token = $c->session('token');
    my ($success, $error, $connect) = ($config->{on_success}, $config->{on_error}, $config->{on_connect});
    my ($args, $fetch, $map) = ($self->providers->{$provider}->{args}, $self->providers->{$provider}->{fetch}, {%{$self->providers->{$provider}->{map}}});

    $c->delay(
      sub {   
        my $delay = shift;
        # Only get the token from $provider if the current one isn't expired
        if ( $token->{$provider} && $token->{$provider}->{access_token} && $token->{$provider}->{expires_at} && time < $token->{$provider}->{expires_at} ) {
          my $cb = $delay->begin;
          $c->$cb(undef, $token->{$provider}); 
        } else {
          my $args = {redirect_uri => $c->url_for('connectprovider', {provider => $provider})->userinfo(undef)->to_abs, %$args};
          $c->oauth2->get_token($provider => $args, $delay->begin);
        }
      },
      sub {
        my ($delay, $err, $data) = @_;
        # If already connected to $provider, no reason to go through this again
        # All this does is pull down basic info / email and store locally
        return $c->redirect_to($success) if $connect->($c, $c->session('id'), $provider);
        unless ( $data->{access_token} ) {
          $c->flash(error => "Could not obtain access token: $err");
          return $c->redirect_to($error);
        }
        $token->{$provider} = $data;
        $token->{$provider}->{expires_at} = time + ($token->{$provider}->{expires_in}||3600);
        $c->session(token => $token);
        $c->ua->get($self->_fetch($fetch, $token->{$provider}->{access_token}), sub {
          my ($ua, $tx) = @_;
          my $json = Mojo::JSON::Pointer->new($tx->res->json);
          if ( my $error_message = $json->get(delete $map->{error}) ) {
            $c->flash(error => $error_message);
            return $c->redirect_to($error);
          }
          $c->session(id => $connect->($c, $json->get($map->{id}))) unless $c->session('id');
          $connect->($c, $c->session('id'), $provider, $tx->res->json, {map { $_ => $json->get($map->{$_}) } keys %$map});
          $c->redirect_to($success);
        });
      },
    );
  });
}

sub _fetch {
  my ($self, $fetch, $token) = @_;
  $fetch =~ s/%token%/$token/g;
  return $fetch;
}

1;
__END__

=encoding utf8

=head1 NAME

Mojolicious::Plugin::OAuth2Accounts - Mojolicious Plugin

=head1 SYNOPSIS

  # Mojolicious
  $self->plugin('OAuth2Accounts');

  # Mojolicious::Lite
  plugin 'OAuth2Accounts';

=head1 DESCRIPTION

L<Mojolicious::Plugin::OAuth2Accounts> is a L<Mojolicious> plugin.

=head1 METHODS

L<Mojolicious::Plugin::OAuth2Accounts> inherits all methods from
L<Mojolicious::Plugin> and implements the following new ones.

=head2 register

  $plugin->register(Mojolicious->new);

Register plugin in L<Mojolicious> application.

=head1 SEE ALSO

L<Mojolicious>, L<Mojolicious::Guides>, L<http://mojolicio.us>.

=cut
