package Mojolicious::Plugin::OAuth2::Fetch;
use Mojo::Base 'Mojolicious::Plugin';

our $VERSION = '0.01';

has on_success => 'success';
has on_error => 'error';
has on_connect => sub {
  my ($c, $oauth2_id, $provider, $json, $results) = @_;
  $c->session('oauth2.me' => {id => $oauth2_id, provider => $provider, json => $json, results => $results});
};
has on_disconnect => '/';

has 'default_provider';
has providers => sub {
  return {
    mocked => {
      args => {
        scope => 'user_about_me email',
      },
      fetch => '/mocked/me?access_token=%token%',
      me => {
        i => 123,
        e => 'a@a.com',
        f => 'John',
        l => 'Doe',
      },
      map => {
        error => {
          message => '/err/0',
        },
        results => {
          id => '/i',
          email => '/e',
          first_name => '/f',
          last_name => '/l',
        },
      },
    },
    facebook => {
      args => {
        scope => 'user_about_me email',
      },
      fetch => 'https://graph.facebook.com/v2.3/me?access_token=%token%',
      map => {
        error => {
          message => '/error/message',
        },
        results => {
          id => '/id',
          email => '/email',
          first_name => '/first_name',
          last_name => '/last_name',
        },
      },
    },
  }
};

sub register {
  my ($self, $app, $config) = @_;

  $self->default_provider($config->{default_provider}) if $config->{default_provider};
  $self->on_success($config->{on_success}) if $config->{on_success};
  $self->on_error($config->{on_error}) if $config->{on_error};
  $self->on_connect($config->{on_connect}) if $config->{on_connect};
  $self->on_disconnect($config->{on_disconnect}) if $config->{on_disconnect};

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

  $app->routes->get("/mocked/me" => sub {
    my $c = shift;
    return $c->render(json => {err => ['Invalid access token']}) unless $c->param('access_token') eq 'fake_token';
    $c->render(json => $self->providers->{mocked}->{me});
  });

  $app->routes->get("/connect" => sub {
    my $c = shift;
    my $provider = $c->session('oauth2.provider');
    return $c->redirect_to('connectprovider', {provider => $provider}) if $provider;
    $c->stash(providers => grep { $self->providers->{$provider}->{key} } keys %{$self->providers});
    $c->render_maybe('connect') or $c->redirect_to('connectprovider', {provider => $self->default_provider});
  });

  $app->routes->get("/connect/:provider" => sub {
    my $c = shift;

    my $provider = $c->param('provider');
    my $token = $c->session('oauth2.token');
    $c->session('oauth2.provider' => $provider) unless $c->session('oauth2.provider');
    $c->session('oauth2.token' => {}) unless $c->session('oauth2.token');

    my $this_provider = $self->providers->{$provider};
    return $c->reply->not_found unless $this_provider && $this_provider->{key};

    $c->delay(
      sub { # Connect 
        my $delay = shift;
        # Only get the token from $provider if the current one isn't expired
        my $this_token = $token->{$provider};
        if ( $this_token && $this_token->{access_token} && $this_token->{expires_at} && time < $this_token->{expires_at} ) {
          $delay->begin(undef, $this_token); 
        } else {
          my $args = {redirect_uri => $c->url_for('connectprovider', {provider => $provider})->userinfo(undef)->to_abs, %{$this_provider->{args}}};
          $c->oauth2->get_token($provider => $args, $delay->begin);
        }
      },
      sub { # Fetch
        my ($delay, $err, $data) = @_;

        # If already connected to $provider, no reason to go through this again
        # All this does is pull down basic info / email and store locally
        return $self->_on_success($c) if $self->_on_connect($c);
        return $self->_on_error($c, "Could not obtain access token: $err") if $err || !$data->{access_token};

        # Store token in cookie session
        $data->{expires_at} = time + ($data->{expires_in}||3600) unless $data->{expires_at};
        $c->session->{token}->{$provider} = $data;

        # Connect to $provider and obtain and store desired info
        $self->_on_connect($c, $data->{access_token});
      },
    );
  });

  $app->routes->get('/disconnect' => sub {
    my $c = shift;
    my $token = $c->session('oauth2.token') || {};
    my $provider = $c->session('oauth2.provider') || '';
    my $me = $c->session('oauth2.me') || {};
    delete $c->session->{$_} foreach keys %{$c->session};
    $token->{$_} = {} foreach keys %$token;
    $c->session('oauth2.token' => $token);
    $c->session('oauth2.provider' => $provider);
    $c->session('oauth2.me' => $me);
    $self->_on_disconnect($c);
  });
}

sub _on_success {
  my ($self, $c) = @_;
  return $c->reply->exception('on_success must not be a ref') if ref $self->on_success;
  $c->redirect_to($self->on_success);
}

sub _on_error {
  my ($self, $c, $error) = @_;
  return $c->reply->exception('on_error must not be a ref') if ref $self->on_error;
  return undef unless $error;
  $c->flash(error => $error);
  $c->redirect_to($self->on_error);
}

sub _on_connect {
  my ($self, $c, $access_token) = @_;
  return $c->reply->exception('on_connect must be a coderef') unless ref $self->on_connect eq 'CODE';
  if ( $access_token ) {
    my $p = $self->providers->{$c->param('provider')};
    my $fetch = $p->{fetch};
    $fetch =~ s/%token%/$access_token/g;
    $c->ua->get($fetch => sub {
      my ($ua, $tx) = @_;
      my $json = Mojo::JSON::Pointer->new($tx->res->json);
      my $error_map = $p->{map}->{error};
      return if $self->_on_error($c, $json->get($error_map->{message}));
      my $results_map = $p->{map}->{results};
      my $results = {map { $_ => $json->get($results_map->{$_}) } keys %$results_map};
      # Link providers
      $c->session('oauth2.id' => $self->on_connect->($c, $results->{id})) unless $c->session('oauth2.id');
      # Store provider
      $self->on_connect->($c, $c->session('oauth2.id'), $c->param('provider'), $tx->res->json, $results);
      $self->_on_success($c);
    });
  } else {
    # Lookup provider
    $self->on_connect->($c, $c->session('oauth2.id'), $c->param('provider'));
  }
}

sub _on_disconnect {
  my ($self, $c) = @_;
  return $c->reply->exception('on_disconnect must not be a ref') if ref $self->on_disconnect;
  $c->redirect_to($self->on_disconnect);
}

1;

__DATA__

@@ success.html.ep
Success!

@@ error.html.ep
% if ( my $error = flash 'error' ) {
Error!  <%= $error %>
% }

@@ connect.html.ep
Connect!

@@ disconnect.html.ep
Disconnect!

__END__

=encoding utf8

=head1 NAME

Mojolicious::Plugin::OAuth2::Fetch - Mojolicious Plugin

=head1 SYNOPSIS

  # Mojolicious
  $self->plugin('OAuth2::Fetch');

  # Mojolicious::Lite
  plugin 'OAuth2::Fetch';

=head1 DESCRIPTION

L<Mojolicious::Plugin::OAuth2::Fetch> is a L<Mojolicious> plugin.

=head1 METHODS

L<Mojolicious::Plugin::OAuth2::Fetch> inherits all methods from
L<Mojolicious::Plugin> and implements the following new ones.

=head2 register

  $plugin->register(Mojolicious->new);

Register plugin in L<Mojolicious> application.

=head1 SEE ALSO

L<Mojolicious>, L<Mojolicious::Guides>, L<http://mojolicio.us>.

=cut
