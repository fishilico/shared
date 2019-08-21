#!/usr/bin/env python3
"""Base primitives to communicate with a web server

This is like Python’s Requests Library, but with a more low-level approach
"""

import argparse
import http.cookiejar
import json
import logging
import urllib.parse
import urllib.request
import ssl


logger = logging.getLogger(__name__)


# List some well-known user agents
# cf. https://developers.whatismybrowser.com/useragents/explore/
USER_AGENTS = {
    'android-4':
        'Mozilla/5.0 (Linux; U; Android 2.2) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
    'chrome-72_linux-x64':
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.119 Safari/537.36',
    'chrome-74_android-9':
        'Mozilla/5.0 (Linux; Android 9; SM-G960F Build/PPR1.180610.011; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.157 Mobile Safari/537.36',  # noqa
    'chrome-74_windows-x64':
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36',  # noqa
    'firefox-65_linux-x64':
        'Mozilla/5.0 (X11; Linux x86_64; rv:65.0) Gecko/20100101 Firefox/65.0',
    'msie-10_windows-x64':
        'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)',
}


def disable_ssl_cert_check_opener():
    """Do not verify the HTTPS certificate

    This enables using a HTTPS proxy wuch as BurpSuite
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # noqa
    return urllib.request.HTTPSHandler(context=ctx)


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Perform HTTP requests without following HTTP redirects"""
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        pass


class WebSiteContext(object):
    """Context associated with a website"""
    def __init__(self, base_url, disable_ssl_check=False, is_ajax_api=False):
        # base_url is https://my-website.example.org/sub-directory
        self.base_url = base_url.rstrip('/')
        self.cookie_jar = http.cookiejar.CookieJar()
        self.disable_ssl_check = disable_ssl_check

        self.default_headers = {
            'Referer': self.base_url + '/',
            'Connection': 'close',
            'User-Agent': USER_AGENTS['chrome-74_windows-x64'],
            'Accept': '*/*',
        }

        if is_ajax_api:
            # Add a header added by most browsers
            self.default_headers['X-Requested-With'] = 'XMLHttpRequest'

        if disable_ssl_check:
            self.ssl_opener = disable_ssl_cert_check_opener()
        else:
            self.ssl_opener = urllib.request.HTTPSHandler()

    def get_cookie(self, name):
        """Retrieve the value of a cookie from the cookie jar"""
        for cookie in self.cookie_jar:
            if cookie.name == name:
                return cookie.value
        return None

    def http_request(self, method, uri, data=None, headers=None, read_all=False):
        """Perform a HTTP request"""
        # Fill the headers using the default ones
        if headers is None:
            headers = {}
        for key, value in self.default_headers.items():
            if key not in headers:
                headers[key] = value

        assert uri.startswith('/')  # uri must be relative
        url = self.base_url + uri
        logger.debug("HTTP %s %r", method, url)
        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        cookies = urllib.request.HTTPCookieProcessor(cookiejar=self.cookie_jar)
        opener = urllib.request.build_opener(self.ssl_opener, cookies, NoRedirectHandler())
        try:
            with opener.open(req) as resp:
                if resp.status not in (200, 204):
                    logger.error("Request to %r returned HTTP status %d", uri, resp.status)
                    raise ValueError(resp)
                content_length = int(resp.getheader('Content-Length', '0'))
                if content_length:
                    data = resp.read(content_length)
                elif read_all:
                    data = resp.read()
                else:
                    data = None
                return resp, data
        except urllib.error.HTTPError as exc:
            # If there are HTTP errors, they can be caught here
            if exc.status in (400, 401, 403, 405):
                # There may be an error message in the content
                content_length = int(exc.getheader('Content-Length', '0'))
                content_type = exc.getheader('Content-Type', '')
                data = exc.read(content_length) if content_length else None
                if content_length and content_type == 'application/json;charset=UTF-8':
                    data = json.loads(data)
                logger.error("Got HTTP %d %r", exc.status, data)
            raise exc

    @staticmethod
    def decode_http_json_response(resp, data):
        """Decode the response from a JSON REST API"""
        content_type = resp.getheader('Content-Type', '')
        if content_type != 'application/json;charset=UTF-8':
            logger.error("Unexpected HTTP content type for JSON response: %r", content_type)
            raise ValueError
        return json.loads(data)

    def get(self, uri, **get_params):
        """Perform a GET request with GET parameters"""
        data = urllib.parse.urlencode(get_params)
        if data:
            uri += '?' + data
        return self.http_request('GET', uri)

    def get_and_json(self, uri, **get_params):
        """Perform a GET request and expect a JSON response"""
        resp, data = self.get(uri, **get_params)
        return self.decode_http_json_response(resp, data)

    def post(self, uri, **post_params):
        """Perform a POST request with POST parameters"""
        data = urllib.parse.urlencode(post_params).encode('utf-8')
        return self.http_request('POST', uri, data=data, headers={
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        })

    def post_json(self, uri, json_data):
        """Perform a POST request with JSON parameters"""
        data = json.dumps(json_data).encode('utf-8')
        return self.http_request('POST', uri, data=data, headers={
            'Content-Type': 'application/json',
        })

    def post_and_json(self, uri, **post_params):
        """Perform a POST request and expect a JSON response"""
        resp, data = self.post(uri, **post_params)
        return self.decode_http_json_response(resp, data)

    def post_json_and_json(self, uri, json_data):
        """Perform a POST-JSON request and expect a JSON response"""
        resp, data = self.post_json(uri, json_data)
        return self.decode_http_json_response(resp, data)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Connect to a website")
    parser.add_argument('url', metavar="URL", type=str,
                        help="HTTP(S) URL of the used website")
    parser.add_argument('-S', '--disable-ssl', action='store_true',
                        help="Disable SSL/TLS checks")
    args = parser.parse_args(argv)

    logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)

    ctx = WebSiteContext(args.url, disable_ssl_check=args.disable_ssl)
    resp, main_page = ctx.http_request('GET', '/', read_all=True)
    logger.debug("Response code: %d", resp.status)
    print(main_page)


if __name__ == '__main__':
    main()
