#!/usr/bin/env python
# -*- coding:UTF-8 -*-
# Copyright (c) 2019 Nicolas Iooss
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""List the GitHub repositories of a user"""
import argparse
import json
import logging
from pathlib import Path
import re
import subprocess
import sys
import urllib.parse

import requests


# pylint: disable=invalid-name
logger = logging.getLogger(__name__)


def parse_link_headers(link_header):
    """Parse a Link header from the pagination API

    https://developer.github.com/v3/#pagination
    """
    result = {}
    original_link_header = link_header
    while link_header:
        matches = re.match(r'^<([^>]+)>; rel="([a-z]+)"(?:|, (.*))$', link_header)
        if not matches:
            logger.error("Unsable to parse Link header: %r", original_link_header)
            raise ValueError("Unable to parse remaining Link header {}".format(repr(link_header)))
        url, rel, link_header = matches.groups()
        obj = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(obj.query)
        per_page = int(query['per_page'][0])
        page = int(query['page'][0])
        if rel in result:
            logger.warning("Duplicated %r in Link header %r", rel, original_link_header)
        result[rel] = {
            'url': url,
            'per_page': per_page,
            'page': page,
        }
    return result


def selfchecks_parse_link_headers():
    """Sanity checks for parse_link_headers()"""
    # from https://api.github.com/users/github/repos?per_page=1
    gh_link = ('<https://api.github.com/user/9919/repos?per_page=1&page=2>; rel="next", ' +
               '<https://api.github.com/user/9919/repos?per_page=1&page=322>; rel="last"')
    links = parse_link_headers(gh_link)
    assert links == {
        'next': {
            'url': 'https://api.github.com/user/9919/repos?per_page=1&page=2',
            'per_page': 1,
            'page': 2,
        },
        'last': {
            'url': 'https://api.github.com/user/9919/repos?per_page=1&page=322',
            'per_page': 1,
            'page': 322,
        }
    }


selfchecks_parse_link_headers()


def list_github_user_repos(github_api_url, username, per_page=100):
    """Use GitHub's API to list the repositories of a user

    https://developer.github.com/v3/repos/#list-user-repositories
    """
    endpoint_url = '{}/users/{}/repos?per_page={}'.format(github_api_url, username, per_page)
    response = requests.get(endpoint_url, allow_redirects=False)
    if response.status_code != 200:
        raise ValueError("unsuccessful HTTP status code {}".format(response.status_code))

    # Craft the result using pagination
    result = response.json()

    # Grab pagination headers
    if 'Link' not in response.headers:
        return result

    links = parse_link_headers(response.headers['Link'])
    # Truncate the results if the pagination headers are invalid
    if 'next' not in links or links['next']['per_page'] != per_page or links['next']['page'] != 2:
        logger.error("Invalid next part in Link header: %r", response.headers['Link'])
        return result
    if 'last' not in links or links['last']['per_page'] != per_page or links['last']['page'] < 2:
        logger.error("Invalid last part in Link header: %r", response.headers['Link'])
        return result
    last_page = links['last']['page']

    while True:
        next_page = links['next']['page']
        logger.debug("Requesting page %d/%d", next_page, last_page)
        response = requests.get(
            links['next']['url'],
            allow_redirects=False)
        if response.status_code != 200:
            raise ValueError("unsuccessful HTTP status code {}".format(response.status_code))
        result += response.json()

        links = parse_link_headers(response.headers['Link'])
        if 'next' not in links:
            break

        if links['next']['page'] != next_page + 1:
            logger.error("Invalid next part in Link header of page %d: %r", next_page, response.headers['Link'])
            break
        if 'last' not in links or links['last']['per_page'] != per_page:
            logger.error("Invalid last part in Link header of page %d: %r", next_page, response.headers['Link'])
            break

    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="List the GitHub repositories of a user")
    parser.add_argument('user', metavar="USERNAME", type=str,
                        help="username to list the repositories from")
    parser.add_argument('-c', '--clone', action='store_true',
                        help="clone the repositories")
    parser.add_argument('-j', '--json-out', metavar='OUTPUT_FILE', type=Path,
                        help="write the JSON metadata to this file")
    parser.add_argument('-o', '--output', metavar='OUTPUT_DIR', type=Path,
                        help="output directory where to clone the repositories")
    parser.add_argument('-p', '--perpage', type=int, default=100,
                        help="number of results on each page, for the API (100 by default)")
    parser.add_argument('-s', '--ssh', action='store_true',
                        help="use SSH instead of HTTPS to access the repositories")
    parser.add_argument('-u', '--url', type=str, default='https://api.github.com',
                        help="base URL of the targetted GitHub instance")
    args = parser.parse_args(argv)

    logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)

    try:
        repos = list_github_user_repos(args.url, args.user, per_page=args.perpage)
    except ValueError as exc:
        logger.error("Error: %s", exc)
        return 1

    logger.info("Got %d repositories for %r", len(repos), args.user)

    if args.json_out:
        with args.json_out.open('w') as fout:
            json.dump(repos, fout, indent=2)
        logger.info("Project list saved to %r", str(args.json_out))

    retval = 0
    for repo_info in repos:
        repo_name = repo_info['name']
        repo_full_name = repo_info['full_name']
        repo_clone_dirname = repo_full_name.split('/', 1)[-1]
        if args.ssh:
            repo_url = repo_info['ssh_url']
        else:
            repo_url = repo_info['clone_url']

        # Do not print the path if it is expected
        if not repo_url.endswith('/{}.git'.format(repo_full_name)):
            logger.warning("Unexpected URL %r for path %r", repo_url, repo_full_name)
            print("{} {} {}".format(repo_name, repo_full_name, repo_url))
        else:
            if repo_clone_dirname == repo_name:
                print("{} {}".format(repo_name, repo_url))
            else:
                logger.warning("Unexpected path %r for name %r", repo_clone_dirname, repo_name)
                print("{} {} {}".format(repo_name, repo_clone_dirname, repo_url))

        # Check that the path is sane enough for an actual path component
        if not re.match(r'^[0-9A-Za-z_-]+$', repo_clone_dirname):
            logger.error("Unsafe project path name %r, refusing to clone", repo_clone_dirname)
            retval = 1
            continue

        if args.clone:
            if args.output:
                args.output.mkdir(exist_ok=True)
                outputdir = args.output / repo_clone_dirname
            else:
                outputdir = Path(repo_clone_dirname)

            if outputdir.exists():
                logger.info("Already cloned to %r", str(outputdir))
            else:
                # Clone the project
                cmdline = ['git', 'clone', repo_url, str(outputdir)]
                logger.info("Running %s", ' '.join(cmdline))
                subprocess.call(cmdline)

    return retval


if __name__ == '__main__':
    sys.exit(main())
