#!/usr/bin/env python
# -*- coding:UTF-8 -*-
# Copyright (c) 2018 Nicolas Iooss
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
"""
Update in each Dockerfile the configuration that is used.
This grabs the record of "make list-nobuild" in the output of Docker executions.
"""
import argparse
import logging
import os.path
import re
import sys


DOCKERFILE_PREFIX = os.path.join(os.path.dirname(__file__), 'Dockerfile-')

logger = logging.getLogger(__name__)


def update_dockerfile(image_name, make_list_nobuild_output):
    """Update a Dockerfile accordingly to the recorded output"""
    dockerfile = DOCKERFILE_PREFIX + image_name
    with open(dockerfile, 'r') as fdockerfile:
        old_content = fdockerfile.read()
    # Drop the previous results
    content = old_content.split('\n# make list-nobuild:\n', 1)[0]
    # Append the new ones
    content += '\n# make list-nobuild:\n'
    content += ''.join('#    {}\n'.format(line) for line in make_list_nobuild_output)
    # Update the file if needed
    if content != old_content:
        logger.info("Updating image %r Dockerfile", image_name)
        with open(dockerfile, 'w') as fdockerfile:
            fdockerfile.write(content)
    else:
        logger.info("Dockerfile for image %r was already up to date", image_name)


def parse_log_file(filepath):
    """Parse a log file to fill "make list-nobuild" in Dockerfiles"""
    retval = True
    logger.info("Processing log %r", filepath)
    current_image = None
    current_output = None
    with open(filepath, 'rb') as flog:
        for bin_line in flog:
            line = bin_line.decode('utf-8', 'replace')
            if current_output is None:
                # Grab current image name
                m = re.match(r'^            Using image shared-(\S+)\.\.\.\s*$', line)
                if m:
                    if current_image:
                        logger.error("Image %r failed tests", current_image)
                        retval = False
                    current_image = m.group(1)
                if re.match(r'^\* Output of make list-nobuild +\*\s*$', line):
                    current_output = []
            else:
                if re.match(r'^\*+\s*$', line):
                    # Ignore "*********" line
                    continue
                elif 'Done running tests.' in line:
                    # Last line
                    if not current_image:
                        logger.error("Found 'make list-nobuild' output not attached to an image")
                        retval = False
                    else:
                        update_dockerfile(current_image, current_output)
                    current_output = None
                    current_image = None
                elif line.rstrip() in (
                        '0014:err:service:process_send_command service protocol error - failed to read pipe r = 0  count = 0!',  # noqa
                        '0015:err:service:process_send_command service protocol error - failed to read pipe r = 0  count = 0!',  # noqa
                        '0016:err:service:process_send_command service protocol error - failed to read pipe r = 0  count = 0!',  # noqa
                        '0017:err:service:process_send_command service protocol error - failed to read pipe r = 0  count = 0!',  # noqa
                        '007c:err:rpc:RpcAssoc_BindConnection receive failed with error 1726',
                        '008c:err:rpc:I_RpcReceive we got fault packet with status 0x1c010003',
                        '009c:err:rpc:I_RpcReceive we got fault packet with status 0x1c010003',
                        '00a0:err:rpc:I_RpcReceive we got fault packet with status 0x1c010003',
                        ):
                    # Ignore lines generated from stray instances of Wine
                    continue
                else:
                    current_output.append(line.rstrip())
    return retval


def main(argv=None):
    """Program entry point"""
    parser = argparse.ArgumentParser(
        description="Parse logs and update make list-nobuild records")
    parser.add_argument('files', metavar='FILE', nargs='+',
                        help="log files (eg. output of 'script' command)")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="show debug messages")

    args = parser.parse_args(argv)
    logging.basicConfig(format='[%(levelname)-5s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    for filepath in args.files:
        if not parse_log_file(filepath):
            return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
