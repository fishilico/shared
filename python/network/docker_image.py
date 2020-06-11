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
"""Get information about Docker images

This retrieves information about a Docker image and can download an extract it,
even when the host appears not to be compatible with the container (contrary to
docker pull, podman pull, buildah, etc.).

Usage example:

    # List tags of official Alpine and Debian images
    # (https://hub.docker.com/_/alpine and https://hub.docker.com/_/debian)
    docker_image.py -l alpine debian

    # Download Centos 8 image
    docker_image.py -o docker_cache.out centos:8

    # Download Official Microsoft SQL Server Express Edition images for Windows Containers
    # (https://hub.docker.com/r/microsoft/mssql-server-windows-express/)
    docker_image.py -o docker_cache.out microsoft/mssql-server-windows-express

    # Download Official images for Microsoft SQL Server on Linux for Docker Engine
    # (https://hub.docker.com/_/microsoft-mssql-server)
    docker_image.py -o docker_cache.out -r mcr.microsoft.com mssql/server:latest-ubuntu

Documentation:
* https://docs.docker.com/registry/spec/api/
  Specification of Docker registry API
* https://docs.docker.com/registry/spec/auth/scope/
  Token Scope Documentation

@author: Nicolas Iooss
@license: MIT
"""
import argparse
import hashlib
import json
import logging
from pathlib import Path
import os
import re

import requests


# pylint: disable=invalid-name
logger = logging.getLogger(__name__)


DOCKER_REGISTRY = 'https://registry-1.docker.io'


def normalize_docker_registry_name(image_name):
    """Normalize the name of an image for Docker registry"""
    if image_name.startswith('_/'):
        # On Docker Hub, "_/name" means "library/name"
        return 'library/{}'.format(image_name[2:])

    if '/' not in image_name:
        # Official images are located in library
        return 'library/{}'.format(image_name)

    return image_name


def split_auth_header(header):
    """Split comma-separate key=value fields from a WWW-Authenticate header"""
    fields = {}
    remaining = header.strip()
    while remaining:
        matches = re.match(r'^([0-9a-zA-Z]+)="([^"]+)"(?:,\s*(.+))?$', remaining)
        if not matches:
            # Without quotes
            matches = re.match(r'^([0-9a-zA-Z]+)=([^",]+)(?:,\s*(.+))?$', remaining)
        if not matches:
            raise ValueError("Unable to parse auth header {}".format(repr(header)))
        key, value, remaining = matches.groups()
        fields[key] = value
    return fields


class DockerRegistry:
    """Handle information about a connection to a docker registry"""
    def __init__(self, url, trust_filesystem=False):
        url = url.rstrip('/')
        # Prepend https:// automatically
        if '://' not in url:
            url = 'https://{}'.format(url)

        self.url = url
        self.headers = {}
        self.last_auth_scope = None
        self.trust_filesystem = trust_filesystem

        # Set of layer digests that have already been validated in cache
        # Dictionary of "sha256:xxxxx" -> size of layer
        self.cached_layer_digests = {}

        # Authenticate with the registry, using /v2/ ping response
        # cf. https://github.com/containers/image/blob/v5.1.0/docker/docker_client.go#L508
        # and https://github.com/containers/image/pull/211#issuecomment-273426236
        # ... or not. Such a request does not work on gcr.io with an empty scope,
        # so rely on requests using ping(scope=...) to authenticate in a
        # "lazy evaluation way" with the registry.
        # self.ping()

    def normalize_name_if_needed(self, image_name):
        """Normalize the name of an image for Docker registry, if the registry is Docker's one"""
        if self.url == DOCKER_REGISTRY:
            return normalize_docker_registry_name(image_name)
        return image_name

    def ping(self, scope=None):
        """Ping the registry, authenticating if needed"""
        if 'Authorization' in self.headers and scope != self.last_auth_scope:
            # Invalidate the authentication header
            del self.headers['Authorization']

        ping_url = '{}/v2/'.format(self.url)
        ping_response = requests.get(ping_url, headers=self.headers, allow_redirects=False)
        if ping_response.status_code == 200:
            logger.debug("Ping OK, result=%r", ping_response.json())
            return ping_response.json()

        if ping_response.status_code == 401:
            # Authenticate to the registry
            auth_header = ping_response.headers['WWW-Authenticate']
            kind, fields_str = auth_header.split(' ', 1)
            if kind == 'Bearer':
                logger.debug("Authenticating to %r with scope=%r", fields_str, scope)
                fields = split_auth_header(fields_str)
                auth_realm = fields['realm']
                auth_service = fields.get('service')

                if not auth_realm.startswith('https://'):
                    logger.error("Authentication realm %r is not HTTPS", auth_realm)
                    raise ValueError("Authentication realm is not HTTPS, refusing to use it")
                auth_params = {}
                if auth_service:
                    auth_params['service'] = auth_service
                if scope:
                    auth_params['scope'] = scope

                auth_response = requests.get(auth_realm, params=auth_params, allow_redirects=False)
                if auth_response.status_code != 200:
                    logger.error("Unexpected auth response code %d", auth_response.status_code)
                    raise ValueError("Unexpected auth response")

                # Extract the authentication token from the response and put it in an Authorization header
                auth_resp_json = auth_response.json()
                auth_token = auth_resp_json['token']
                self.headers['Authorization'] = 'Bearer {}'.format(auth_token)
                self.last_auth_scope = scope

                # Try pinging again
                ping_response = requests.get(ping_url, headers=self.headers, allow_redirects=False)
                if ping_response.status_code != 200:
                    logger.error("Unsuccessful authenticated ping response code %d", ping_response.status_code)
                    raise ValueError("Unsuccessful authenticated ping response")
                # https://registry-1.docker.io replies with '{}'
                # https://gcr.io replies with ''
                # https://quay.io replies with 'true'
                logger.debug("Authentication OK, ping result=%r", ping_response.content)
                return ping_response.content

            raise ValueError("Unexpected authentication header kind {}".format(repr(auth_header)))

        logger.error("Unexpected ping response code %d", ping_response.status_code)
        raise ValueError("Unexpected ping response")

    def get_with_scope(self, url, scope, headers=None, allow_redirects=False, stream=False):
        """Perform a HTTP GET request with the specified scope"""
        assert scope
        if self.last_auth_scope != scope:
            self.ping(scope=scope)
        used_headers = self.headers
        if headers:
            used_headers = used_headers.copy()
            used_headers.update(headers)
        response = requests.get(
            url,
            headers=used_headers,
            allow_redirects=allow_redirects,
            stream=stream)
        if response.status_code == 401:
            # Launch an authentication procedure (the token may have expired)
            logger.debug("Trying to authenticate again, to get %r", url)
            self.last_auth_scope = None
            self.ping(scope=scope)

            # Recompute the headers with the new authentication header value
            used_headers = self.headers
            if headers:
                used_headers = used_headers.copy()
                used_headers.update(headers)
            response = requests.get(
                url,
                headers=used_headers,
                allow_redirects=allow_redirects,
                stream=stream)
        return response

    def list_tags(self, image_name):
        """List the available tags of an image"""
        image_name = self.normalize_name_if_needed(image_name)
        response = self.get_with_scope(
            '{}/v2/{}/tags/list'.format(self.url, image_name),
            scope='repository:{}:pull'.format(image_name),
            allow_redirects=True)
        if response.status_code != 200:
            logger.error("Unable to retrieve the tags of image %r: HTTP error %d",
                         image_name, response.status_code)
            logger.error("... Response JSON: %r", response.json())
            raise ValueError("HTTP error {}".format(response.status_code))

        data = response.json()
        if data['name'] != image_name:
            logger.error("Received data %r", data)
            raise ValueError("Mismatched image name in data: {} != {}".format(
                repr(data['name']), repr(image_name)))
        return data['tags']

    def get_manifest(self, image_name, tag_name):
        """Retrieve the manifest of an image with the specified tag"""
        image_name = self.normalize_name_if_needed(image_name)
        response = self.get_with_scope(
            '{}/v2/{}/manifests/{}'.format(self.url, image_name, tag_name),
            scope='repository:{}:pull'.format(image_name),
            headers={
                # Request Image Manifest Version 2, Schema 2, if available
                'Accept': (
                    'application/vnd.docker.distribution.manifest.v2+json, ' +
                    'application/vnd.docker.distribution.manifest.v1+json'
                ),
            },
            allow_redirects=True)
        if response.status_code != 200:
            logger.error("Unable to retrieve the manifest of %r:%r: HTTP error %d",
                         image_name, tag_name, response.status_code)
            logger.error("... Response JSON: %r", response.json())
            raise ValueError("HTTP error {}".format(response.status_code))

        content_type = response.headers['content-type']
        if content_type == 'application/vnd.docker.distribution.manifest.v1+json':
            # Return a v1 manifest
            manifest = response.json()
            return {'v1': manifest}

        if content_type == 'application/vnd.docker.distribution.manifest.v2+json':
            # Return a v2 manifest, plus configuration
            manifest = response.json()
            result = {'v2': manifest}
            try:
                config_type = manifest['config']['mediaType']
            except KeyError:
                pass
            else:
                if config_type == 'application/vnd.docker.container.image.v1+json':
                    # Request the configuration
                    response = self.get_with_scope(
                        '{}/v2/{}/manifests/{}'.format(self.url, image_name, tag_name),
                        scope='repository:{}:pull'.format(image_name),
                        headers={'Accept': config_type},
                        allow_redirects=True)
                    if response.status_code != 200:
                        # This may happen, for example with the following error:
                        # {'errors': [{'code': 'MANIFEST_INVALID', 'message': 'manifest invalid', 'detail': {}}]}
                        # In this case, the v2 manifest is still valid, even though it does not have a config
                        logger.warning("Unable to retrieve the manifest v2 config of %r:%r: HTTP error %d",
                                       image_name, tag_name, response.status_code)
                        logger.warning("... Response JSON: %r", response.json())
                    else:
                        result['config'] = response.json()
                else:
                    raise ValueError("Unimplemented manifest v2 config type {}".format(repr(config_type)))
            return result

        raise ValueError("Unimplemented manifest content type {}".format(repr(content_type)))

    def download_layer(self, image_name, digest_name, output_path, urls=None):
        """Download a layer according to the specified digest"""
        # If the layer is already known, return its size
        cached_layer_size = self.cached_layer_digests.get(digest_name)
        if cached_layer_size:
            logger.info("Using already-validated %d bytes from %s",
                        cached_layer_size, output_path)
            return cached_layer_size

        # If the output already exists, checks its content
        if output_path.exists():
            if self.trust_filesystem:
                # Trust that the file holds the right content
                total_size = output_path.stat().st_size
                logger.info("Trusting cached %d bytes from %s", total_size, output_path)
                self.cached_layer_digests[digest_name] = total_size
                return total_size

            computed_digest = hashlib.sha256()
            total_size = 0
            with output_path.open('rb') as fout:
                while True:
                    chunk = fout.read(4096)
                    if not chunk:
                        break
                    computed_digest.update(chunk)
                    total_size += len(chunk)
            resulting_name = 'sha256:{}'.format(computed_digest.hexdigest())
            if resulting_name != digest_name:
                raise ValueError("Invalid file {} with mismatched SHA256 digest: {} != {}".format(
                    output_path, repr(resulting_name), repr(digest_name)))
            logger.info("Validated cached %d bytes from %s", total_size, output_path)
            self.cached_layer_digests[digest_name] = total_size
            return total_size

        image_name = self.normalize_name_if_needed(image_name)

        # Download into a ".part" file
        output_part_path = output_path.with_name(output_path.name + '.part')

        if not urls:
            # Allow redirections, here
            response = self.get_with_scope(
                '{}/v2/{}/blobs/{}'.format(self.url, image_name, digest_name),
                scope='repository:{}:pull'.format(image_name),
                allow_redirects=True,
                stream=True)
        else:
            # Use other URLs that the registry
            for foreign_url in urls:
                response = self.get_with_scope(
                    foreign_url,
                    scope='repository:{}:pull'.format(image_name),
                    allow_redirects=True,
                    stream=True)
                if response.status_code == 200:
                    break
                logger.warning("Unable to retrieve layer %r:%r from %r: HTTP error %d",
                               image_name, digest_name, foreign_url, response.status_code)
                try:
                    logger.warning("... Response JSON: %r", response.json())
                except json.JSONDecodeError:
                    # Some HTTP 404 errors do not provide a JSON response
                    logger.warning("... Response (not JSON): %r", response.content)
                # Continuing with other foreign URL...
                continue
            if response.status_code != 200:
                logger.error("Unable to retrieve layer %r:%r using foreign URL: HTTP error %d",
                             image_name, digest_name, response.status_code)
                raise ValueError("HTTP error {}".format(response.status_code))

        if response.status_code != 200:
            logger.error("Unable to retrieve layer %r:%r: HTTP error %d",
                         image_name, digest_name, response.status_code)
            logger.error("... Response JSON: %r", response.json())
            raise ValueError("HTTP error {}".format(response.status_code))

        total_size = 0
        computed_digest = hashlib.sha256()
        with output_part_path.open('wb') as fout:
            for chunk in response.iter_content(chunk_size=4096):
                computed_digest.update(chunk)
                while chunk:
                    written = fout.write(chunk)
                    if written == 0:
                        raise IOError("Unable to write to layer output file {}".format(output_part_path))
                    total_size += written
                    chunk = chunk[written:]
        resulting_name = 'sha256:{}'.format(computed_digest.hexdigest())
        if resulting_name != digest_name:
            raise ValueError("Mismatched SHA256 digest: {} != {}".format(
                repr(resulting_name), repr(digest_name)))
        os.replace(output_part_path, output_path)
        logger.info("Downloaded %d bytes to %s", total_size, output_path)
        self.cached_layer_digests[digest_name] = total_size
        return total_size

    def download_image(self, image_name, tag_name, output_path):
        """Download an image into the given output directory and return its manifest"""
        # Start by downloading the manifest
        image_name = self.normalize_name_if_needed(image_name)
        manifest = self.get_manifest(image_name, tag_name)

        # Save the manifest somewhere
        manifest_escaped_name = '{}__{}.manifest.json'.format(image_name, tag_name)
        manifest_escaped_name = manifest_escaped_name.replace('/', '__')
        manifest_escaped_name = manifest_escaped_name.replace('\\', '__')
        manifest_escaped_name = manifest_escaped_name.replace(':', '__')
        if not re.match(r'^[0-9A-Za-z_.-]+$', manifest_escaped_name):
            logger.error("Unescaped characters present in name %r from %r:%r",
                         manifest_escaped_name, image_name, tag_name)
            raise ValueError("Unable to save manifest to {}".format(repr(manifest_escaped_name)))
        with (output_path / manifest_escaped_name).open('w') as fout:
            json.dump(manifest, fout, indent=2)
            fout.write('\n')
        logger.info("Saved %s:%s manifest to %r", image_name, tag_name, manifest_escaped_name)

        # Grab all layers
        downloaded_layers = set()
        if 'v2' in manifest:
            for layer in manifest['v2']['layers']:
                expected_size = layer['size']
                digest_name = layer['digest']
                media_type = layer['mediaType']
                if digest_name in downloaded_layers:
                    continue
                if not re.match(r'^[0-9a-z]+:[0-9a-f]+$', digest_name):
                    raise ValueError("Unexpected layer digest format: {}".format(repr(digest_name)))

                # Retrieve foreign URLs
                foreign_urls = None
                if media_type == 'application/vnd.docker.image.rootfs.diff.tar.gzip':
                    pass
                elif media_type == 'application/vnd.docker.image.rootfs.foreign.diff.tar.gzip':
                    foreign_urls = layer.get('urls')
                    if not foreign_urls:
                        logger.warning("No foreign URLs for foreign layer %r", layer)
                else:
                    logger.warning("Unknown layer media type: %r", layer)

                layer_path = output_path / (digest_name.replace(':', '_') + '.tar.gz')
                downloaded_size = self.download_layer(image_name, digest_name, layer_path, urls=foreign_urls)
                if downloaded_size != expected_size:
                    raise ValueError("Mismatched downloaded size for layer {}: {} != {}".format(
                        digest_name, expected_size, downloaded_size))
                downloaded_layers.add(digest_name)

        for v1_key in ('v1', 'config'):
            if v1_key not in manifest:
                continue
            for layer in manifest[v1_key]['fsLayers']:
                digest_name = layer['blobSum']
                if digest_name in downloaded_layers:
                    continue
                if not re.match(r'^[0-9a-z]+:[0-9a-f]+$', digest_name):
                    raise ValueError("Unexpected layer digest format: {}".format(repr(digest_name)))
                layer_path = output_path / (digest_name.replace(':', '_') + '.tar.gz')
                self.download_layer(image_name, digest_name, layer_path)
                downloaded_layers.add(digest_name)

        return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description="Get information about Docker images")
    parser.add_argument('image', metavar="IMAGE", nargs='+', type=str,
                        help="Docker image to use")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="show debug messages")
    parser.add_argument('-l', '--list-tags', action='store_true',
                        help="List image tags")
    parser.add_argument('-o', '--output', type=Path,
                        help="Output directory to download layers to")
    parser.add_argument('-r', '--registry', type=str, default=DOCKER_REGISTRY,
                        help="Docker registry to use (default: {})".format(DOCKER_REGISTRY))
    parser.add_argument('-t', '--tag', nargs='+', type=str,
                        help="Tags to use (default: latest)")
    parser.add_argument('-T', '--trust-filesystem', action='store_true',
                        help="Blindly trust layer files that are already present in the output directory")
    args = parser.parse_args(argv)

    logging.basicConfig(format='[%(levelname)s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    registry = DockerRegistry(args.registry, trust_filesystem=args.trust_filesystem)
    if args.list_tags:
        for image in args.image:
            tags = registry.list_tags(image)
            print("Tags of image {}:".format(repr(image)))
            for tag in tags:
                print("  {}".format(tag))
        return

    if args.output:
        args.output.mkdir(exist_ok=True)

    for image in args.image:
        tag_names = args.tag
        if ':' in image:
            # Overwrite the tag if the image name contains a colon
            image, tag = image.split(':')
            tag_names = (tag, )
        elif not tag_names:
            # Use "latest" by default
            tag_names = ('latest', )

        for tag in tag_names:
            if not args.output:
                # Without an output directory, print the manifest
                print("Manifest of {}:{}:".format(image, tag))
                manifest = registry.get_manifest(image, tag)
                print(json.dumps(manifest, indent=2))
            else:
                # With an output directory, save the manifest and download layers
                logger.info("Downloading %s:%s...", image, tag)
                registry.download_image(image, tag, args.output)


if __name__ == '__main__':
    main()
