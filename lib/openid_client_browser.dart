import 'dart:async';
import 'dart:convert';
import 'dart:html' hide Credential, Client;

import 'openid_client.dart';

export 'openid_client.dart';

class Authenticator {
  final Flow flow;

  final Future<Credential?> credential;

  Authenticator._(this.flow) : credential = _credentialFromUri(flow);

  Authenticator(
    Client client, {
    Iterable<String> scopes = const [],
    Flow? flow,
  }) : this._(
          (flow ??
              Flow.implicit(
                client,
                state: window.localStorage['openid_client:state'],
              ))
            ..scopes.addAll(scopes)
            ..redirectUri = Uri.parse(window.location.href).removeFragment(),
        );

  void authorize() {
    _forgetCredentials();
    window.localStorage['openid_client:state'] = flow.state;
    window.location.href = flow.authenticationUri.toString();
  }

  void logout() async {
    _forgetCredentials();
    var c = await credential;
    if (c == null) return;
    var uri = c.generateLogoutUrl(
        redirectUri: Uri.parse(window.location.href).removeFragment());
    if (uri != null) {
      window.location.href = uri.toString();
    }
  }

  void _forgetCredentials() {
    window.localStorage.remove('openid_client:state');
    window.localStorage.remove('openid_client:auth');
  }

  static Map? _credentialFromHref(String href, {bool reload = true}) {
    Map? q;
    final firstUri = Uri.parse(href);
    final uri = Uri(query: firstUri.fragment);
    q = uri.queryParameters;
    if (q.containsKey('access_token') ||
        q.containsKey('code') ||
        q.containsKey('id_token')) {
      window.localStorage['openid_client:auth'] = json.encode(q);
      window.localStorage['openid_client:state'] = q['state'];
      if (reload) {
        window.location.href = Uri.parse(href).removeFragment().toString();
      }
    }
    return q;
  }

  static Future<Credential?> _credentialFromUri(Flow flow) async {
    Map? q;
    final auth = window.localStorage['openid_client:auth'];
    final href = window.localStorage['openid_client:href'];
    if (auth != null) {
      q = json.decode(auth);
    } else if (href != null) {
      /// Suppose that it is href
      q = _credentialFromHref(href);
    } else {
      _credentialFromHref(window.location.href, reload: false);
    }
    if (q == null) return null;
    if (q.containsKey('access_token') ||
        q.containsKey('code') ||
        q.containsKey('id_token')) {
      return await flow.callback(q.cast());
    }
    return null;
  }
}
