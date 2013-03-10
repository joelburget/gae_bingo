import urlparse
from Crypto.Hash import SHA256

from google.appengine.ext.webapp import RequestHandler

import custom_exceptions
from .gae_bingo import bingo, _iri_to_uri

MIN_SALT_LENGTH = 10

class Redirect(RequestHandler):
    """Handles relative and (optionally) absolute redirects.

    To handle absolute redirects inherit from this class with a subclass
    defining self.salt, a (>= MIN_SALT_LENGTH) string, the same salt used in
    'sign' to generate a signature for the redirect url.
    """
    def get(self):
        """Score conversions and redirect as specified by url params.

        Expects a 'continue' url parameter for the destination,
        and a 'conversion_name' url parameter for each conversion to score.
        """
        cont = self.request.get('continue', default_value='/')
        signature = self.request.get('signature')

        # Check whether redirecting to an absolute or relative url
        netloc = urlparse.urlsplit(cont).netloc
        if netloc:
            if not signature:
                # Disallow absolute urls to prevent arbitrary open redirects
                raise custom_exceptions.InvalidRedirectURLError(
                    "Must use the 'signature' url paramater to redirect to an "
                    "absolute url.")

            try:
                # subclass defines salt
                if sign(cont, self.salt) != signature:
                    raise custom_exceptions.InvalidRedirectURLError(
                        "Improperly signed absolute url redirect.")
            except AttributeError:
                raise custom_exceptions.InvalidRedirectURLError(
                    "This handler is not configured to accept absolute url "
                    "redirects.")

        conversion_names = self.request.get_all('conversion_name')

        if len(conversion_names):
            bingo(conversion_names)

        self.redirect(_iri_to_uri(cont))


def sign(url, salt):
    """Sign the url using salt.

    Use the resulting 32 characters as the signature url parameter for a
    GAE/Bingo redirect to an absolute url.

    Note: This is not necessary for relative url redirects.

    Example:
    <a href=/gae_bingo/redirect?continue={{url}}&signature={{sign(url, salt)}}>
    """
    assert len(salt) > MIN_SALT_LENGTH, "Use a reasonable length salt."
    h = SHA256.new()
    h.update(salt + url)
    return h.hexdigest()
