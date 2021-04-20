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
"""List the gitlab projects of a user"""
import argparse
import json
import logging
from pathlib import Path
import re
import subprocess
import sys

import requests


# pylint: disable=invalid-name
logger = logging.getLogger(__name__)


def list_gitlab_user_projects(gitlab_url, username, is_group):
    """Use Gitlab's API to list the projects of a user

    https://docs.gitlab.com/ee/api/projects.html#list-user-projects
    """
    if is_group:
        endpoint_url = '{}/api/v4/groups/{}/projects'.format(gitlab_url, username)
    else:
        endpoint_url = '{}/api/v4/users/{}/projects'.format(gitlab_url, username)
    response = requests.get(endpoint_url, allow_redirects=False)
    if response.status_code != 200:
        raise ValueError("unsuccessful HTTP status code {}".format(response.status_code))

    # Craft the result using pagination
    result = response.json()

    # Grab pagination headers
    if response.headers['X-Page'] != '1':
        raise ValueError("unexpected X-Page header: {} != 1".format(repr(response.headers['X-Page'])))
    total_number = int(response.headers['X-Total'])
    total_pages = int(response.headers['X-Total-Pages'])
    per_page = int(response.headers['X-Per-Page'])
    current_page = 1
    while response.headers['X-Next-Page']:
        if response.headers['X-Next-Page'] != str(current_page + 1):
            raise ValueError("unexpected X-Next-Page header: {} != {}".format(
                repr(response.headers['X-Next-Page']), current_page + 1))

        current_page += 1
        response = requests.get(
            endpoint_url,
            params={'page': current_page, 'per_page': per_page},
            allow_redirects=False)
        if response.status_code != 200:
            raise ValueError("unsuccessful HTTP status code {}".format(response.status_code))

        if response.headers['X-Page'] != str(current_page):
            raise ValueError("unexpected X-Page header: {} != {}".format(
                repr(response.headers['X-Page']), current_page))
        if response.headers['X-Total'] != str(total_number):
            raise ValueError("unexpected X-Total header: {} != {}".format(
                repr(response.headers['X-Total']), total_number))
        if response.headers['X-Total-Pages'] != str(total_pages):
            raise ValueError("unexpected X-Total-Pages header: {} != {}".format(
                repr(response.headers['X-Total-Pages']), total_pages))
        if response.headers['X-Per-Page'] != str(per_page):
            raise ValueError("unexpected X-Per-Page header: {} != {}".format(
                repr(response.headers['X-Per-Page']), per_page))

        result += response.json()

    if len(result) != total_number:
        logger.warning("X-Total header does not match the number of results: %d != %d",
                       total_number, len(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="List the gitlab projects of a user")
    parser.add_argument('user', metavar="USERNAME", type=str,
                        help="username to list the projects from")
    parser.add_argument('-g', '--group', action='store_true',
                        help="request projects from a group instead of a user")
    parser.add_argument('-c', '--clone', action='store_true',
                        help="clone the projects")
    parser.add_argument('-j', '--json-out', metavar='OUTPUT_FILE', type=Path,
                        help="write the JSON metadata to this file")
    parser.add_argument('-o', '--output', metavar='OUTPUT_DIR', type=Path,
                        help="output directory where to clone the projects")
    parser.add_argument('-s', '--ssh', action='store_true',
                        help="use SSH instead of HTTPS to access the projects")
    parser.add_argument('-u', '--url', type=str, default='https://gitlab.com',
                        help="base URL of the targeted gitlab instance")
    args = parser.parse_args(argv)

    logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)

    try:
        projects = list_gitlab_user_projects(args.url, args.user, args.group)
    except ValueError as exc:
        logger.error("Error: %s", exc)
        return 1

    logger.info("Got %d projects for %r", len(projects), args.user)

    if args.json_out:
        with args.json_out.open('w') as fout:
            json.dump(projects, fout, indent=2)
        logger.info("Project list saved to %r", str(args.json_out))

    retval = 0
    for prj_info in projects:
        prj_name = prj_info['name']
        prj_pathname = prj_info['path']
        if args.ssh:
            prj_url = prj_info['ssh_url_to_repo']
        else:
            prj_url = prj_info['http_url_to_repo']

        # Do not print the path if it is expected
        if not prj_url.endswith('/{}.git'.format(prj_pathname)):
            logger.warning("Unexpected URL %r for path %r", prj_url, prj_pathname)
            print("{} {} {}".format(prj_name, prj_pathname, prj_url))
        else:
            path_from_name = prj_name.lower().replace(' ', '-')
            if prj_pathname == path_from_name:
                print("{} {}".format(prj_name, prj_url))
            else:
                logger.warning("Unexpected path %r for name %r", prj_pathname, prj_name)
                print("{} {} {}".format(prj_name, prj_pathname, prj_url))

        # Check that the path is sane enough for an actual path component
        if not re.match(r'^[0-9A-Za-z_-]+$', prj_pathname):
            logger.error("Unsafe project path name %r, refusing to clone", prj_pathname)
            retval = 1
            continue

        if args.clone:
            if args.output:
                args.output.mkdir(exist_ok=True)
                outputdir = args.output / prj_pathname
            else:
                outputdir = Path(prj_pathname)

            if outputdir.exists():
                logger.info("Already cloned to %r", str(outputdir))
            else:
                # Clone the project
                cmdline = ['git', 'clone', prj_url, str(outputdir)]
                logger.info("Running %s", ' '.join(cmdline))
                subprocess.call(cmdline)

    return retval


if __name__ == '__main__':
    sys.exit(main())
