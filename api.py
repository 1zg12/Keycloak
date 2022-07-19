import json
import logging

from flask import Flask, g
from flask_oidc import OpenIDConnect
import requests
from keycloak import KeycloakOpenID
from oauth2client.client import OAuth2Credentials

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.config.update({
    'SECRET_KEY': 'XlBGtHzPOefRKjiEB9yTcQS0WBHllAcx',
    'TESTING': True,
    'DEBUG': True,
    'OIDC_CLIENT_SECRETS': 'client_secrets.json',
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_REQUIRE_VERIFIED_EMAIL': False,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_OPENID_REALM': 'flask-app',
    'OIDC_SCOPES': ['openid', 'email', 'profile'],
    'OIDC_TOKEN_TYPE_HINT': 'access_token',
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post'
    # 'OIDC_INTROSPECTION_AUTH_METHOD': 'bearer'
})

oidc = OpenIDConnect(app)

keycloak_openid = KeycloakOpenID(server_url="http://localhost:8080/",
                                 client_id="flask",
                                 realm_name="flask-app",
                                 client_secret_key="pww8bSrx1sYC1oLsDkWwj7P2SS6BbpiK")

@app.route('/')
def hello_world():

    if oidc.user_loggedin:
        return ('Hello, %s, <a href="/private">See private</a> '
                '<a href="/logout">Log out</a>') % \
               oidc.user_getfield('preferred_username')
    else:
        return 'Welcome anonymous, <a href="/private">Log in</a>'


@app.route('/private')
@oidc.require_login
def hello_me():
    """Example for protected endpoint that extracts private information from the OpenID Connect id_token.
       Uses the accompanied access_token to access a backend service.
    """

    info = oidc.user_getinfo(['preferred_username', 'email', 'sub'])

    username = info.get('preferred_username')
    email = info.get('email')
    user_id = info.get('sub')

    if user_id in oidc.credentials_store:
        try:

            access_token = OAuth2Credentials.from_json(oidc.credentials_store[user_id]).access_token
            print ('access_token=<%s>' % access_token)
            headers = {'Authorization': 'Bearer %s' % (access_token)}
            # YOLO
            greeting = requests.post('http://localhost:5000/api', headers=headers).text
        except:
            print ("Could not access greeting-service")
            greeting = "Hello %s" % username


    return ("""%s your email is %s and your user_id is %s!
               <ul>
                 <li><a href="/">Home</a></li>
                 <li><a href="//localhost:8080/realms/flask-app/account?referrer=flask-app&referrer_uri=http://localhost:5000/private&">Account</a></li>
                </ul>""" %
            (greeting, email, user_id))


@app.route('/api', methods=['POST'])
@oidc.accept_token(require_token=True)
# @oidc.accept_token(require_token=True, scopes_required=['openid'])
def hello_api():
    """OAuth 2.0 protected API endpoint accessible via AccessToken"""

    return json.dumps({'hello': 'Welcome %s' % g.oidc_token_info['sub']})


@app.route('/logout')
def logout():
    """Performs local logout by removing the session cookie."""
    refresh_token = oidc.get_refresh_token()
    oidc.logout()
    if refresh_token is not None:
        keycloak_openid.logout(refresh_token)
    oidc.logout()
    g.oidc_id_token = None
    return 'Hi, you have been logged out! <a href="/">Return</a>'


if __name__ == '__main__':
    app.run()