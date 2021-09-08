#!/usr/bin/env python3
# -*- coding:UTF-8 -*-
# Copyright (c) 2020 Nicolas Iooss
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
"""Check updates of Docker images and compare them with the known ones"""
import argparse
import json
import logging
from pathlib import Path
import re
import sys

# Use a custom script to interact with Docker API
BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR / '..' / 'python' / 'network'))
try:
    from docker_image import DockerRegistry, DOCKER_REGISTRY
    HAVE_DOCKER_IMAGE = True
except ImportError:
    # Importing docker_image is not necessary with --no-net
    DOCKER_REGISTRY = '(offline)'
    HAVE_DOCKER_IMAGE = False


# Cache file with the list of image tags
IMAGE_TAGS_FILE = BASE_DIR / 'image_tags.json'

# pylint: disable=invalid-name
logger = logging.getLogger(__name__)


def get_used_non_latest_image_tags():
    """Get the list of image tags that are currently used by Docker files"""
    image_tags = {}
    for file_path in BASE_DIR.glob('Dockerfile-*'):
        image_tag = None
        with file_path.open('r') as fdockerfile:
            for line in fdockerfile:
                if line.startswith('FROM '):
                    image_tag = line[5:].strip()
                    break
        if image_tag is None:
            raise ValueError("Invalid file {}: missing FROM line".format(file_path))
        matches = re.match(r'^(?:docker\.io/)?([0-9a-z/-]+)(?::([0-9a-z.-]+))?$', image_tag)
        if not matches:
            raise ValueError("Invalid file {}: unexpected FROM line {}".format(file_path, repr(image_tag)))
        image, tag = matches.groups()

        # Ensure that the tag is defined and is not latest
        if tag is not None and tag != 'latest':
            if image not in image_tags:
                image_tags[image] = set()
            if tag in image_tags[image]:
                raise ValueError("Duplicate use of {}".format(image_tag))
            image_tags[image].add(tag)
    return image_tags


def is_usable_tag(image, tag):
    """Is the image:tag usable in a test Dockerfile?"""
    # Never keep the latest tag, for updatable Dockerfiles
    if tag == 'latest':
        return False

    if image == 'alpine':
        # Filter out ancient releases that are no longer supported on
        # https://wiki.alpinelinux.org/wiki/Alpine_Linux:Releases
        if tag in ('2.6', '2.7', '3.1', '3.2'):
            return False
        # Use 2-number version
        if re.match(r'^3\.[0-9]+$', tag):
            return True
        # Filter out 3-number version
        if re.match(r'^3\.[0-9]+\.[0-9]+$', tag):
            return False
        # Filter out dates
        if re.match(r'^20[0-9]{6}$', tag):
            return False
        # Filter out more recent tags
        if tag in ('3', 'edge'):
            return False

    if image == 'debian':
        # Filter out ancient releases that are no longer supported
        # (they are for example issues with the package manager)
        if tag == 'wheezy-slim':
            return False
        # Do not use images with dynamic names
        if re.match(r'^(oldoldstable|oldstable|stable|sid|testing|unstable)(-slim)?$', tag):
            return False
        # Use slim images with codenames
        if re.match(r'^[a-z]+-slim$', tag):
            return True
        # Filter out not-slim tags with codenames
        if re.match(r'^[a-z]+$', tag):
            return False
        # Filter out backports
        if re.match(r'^[a-z]+-backports$', tag):
            return False
        # Filter out dates
        if re.match(r'^[a-z]+-20[0-9]{6}(-slim)?$', tag):
            return False
        # Filter out version numbers
        if re.match(r'^[0-9]{1,2}(\.[0-9]+(\.[0-9]+)?)?(-slim)?$', tag):
            return False
        # Filter out buggy release candidates
        if re.match(r'^rc-buggy(-20[0-9]{6})?$', tag):
            return False

    if image == 'fedora':
        # Filter out ancient releases that are no longer supported
        # (they are for example issues with the package manager)
        if tag in ('20', '21'):
            return False
        # Use the 2-digit number
        if re.match(r'^[0-9][0-9]$', tag):
            return True
        # Filter out everything else
        if tag in ('26-modular', 'branched', 'heisenbug', 'modular', 'rawhide'):
            return False

    if image == 'ubuntu':
        # Filter out ancient releases that are no longer supported
        # (they are for example issues with the package manager)
        if tag == '10.04':
            return False
        # Use MM.YY date with LTS (Long Term Support)
        if re.match(r'^[0-9][02468]\.04$', tag):
            return True
        # Filter out non-LTS MM.YY and LTS with MM.YY.n format
        if re.match(r'^[0-9][0-9]\.[01][0-9](\.[0-9]+)?$', tag):
            return False
        # Filter out dated tags
        if re.match(r'^[a-z]+-20[0-9]{6}(\.[0-9]+)?$', tag):
            return False
        # Filter out code names
        if re.match(r'^[a-z]+$', tag):
            return False

    # By default, keep the tag
    logger.warning("Unknown tag format: %r %r", image, tag)
    return True


def refresh_image_tags(images, registry_url):
    """Refresh the list of tags for all used images"""
    registry = DockerRegistry(registry_url)
    image_tags = []
    for image in sorted(images):
        logger.info("Refreshing tags of Docker image %r", image)
        for tag in registry.list_tags(image):
            # Filter-out tags according to the image
            if is_usable_tag(image, tag):
                image_tags.append("{}:{}".format(image, tag))
    return image_tags


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check updates of Docker images")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="show debug messages")
    parser.add_argument('-n', '--no-net', action='store_true',
                        help="Do not use the network for refreshing the list of tags")
    parser.add_argument('-r', '--registry', type=str, default=DOCKER_REGISTRY,
                        help="Docker registry to use (default: {})".format(DOCKER_REGISTRY))
    args = parser.parse_args(argv)

    logging.basicConfig(format='[%(levelname)s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    # Parse Dockerfiles to get the list of images
    used_tags = get_used_non_latest_image_tags()

    # Load the available tags
    if not args.no_net:
        if not HAVE_DOCKER_IMAGE:
            # The main reason why importing docker_image would fail is because
            # "import requests" fails
            parser.error("Python requests library is missing. Please use --no-net")
        image_tags = refresh_image_tags(used_tags.keys(), args.registry)
        with IMAGE_TAGS_FILE.open('w') as ftags:
            json.dump(image_tags, ftags, indent=2)
            ftags.write('\n')
    else:
        with IMAGE_TAGS_FILE.open('r') as ftags:
            image_tags = json.load(ftags)

    # Transform the list of image:tags into a proper dict
    available_tags = {}
    for image_tag in image_tags:
        image, tag = image_tag.split(':')
        if image not in available_tags:
            available_tags[image] = set()
        available_tags[image].add(tag)

    # Ensure that the list of images are the same
    assert set(used_tags.keys()) == set(available_tags.keys())

    # Compare them
    has_error = False
    for image, used in sorted(used_tags.items()):
        available = available_tags[image]
        removed = used - available
        missing = available - used
        if removed:
            logger.error("Use of removed tags for %s: %s", image, ', '.join(sorted(removed)))
            has_error = True
        if missing:
            logger.error("Missing new tags for %s: %s", image, ', '.join(sorted(missing)))
            has_error = True

    if has_error:
        sys.exit(1)


if __name__ == '__main__':
    main()
