#!/usr/bin/env python
# -*- coding:UTF-8 -*-
# Copyright (c) 2013 Nicolas Iooss
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
"""Hello world program with argparse and logging

This simple python program has been written for future reference as a base to
write scripts.

This code is compatible with Python 2 >=2.7 and Python 3 >=3.2

@author: Nicolas Iooss
@license: MIT
"""
import argparse
import logging
import os
import sys


logger = logging.getLogger(__name__)


class ColoredFormatter(logging.Formatter):
    """Color logs in terminal"""
    COLORS = {
        'DEBUG': '\033[37m',
        'INFO': '',
        'WARNING': '\033[1;33m',
        'ERROR': '\033[1;31m',
        'CRITICAL': '\033[1;31m',
    }
    COLORS_RESET = '\033[0m'

    def __init__(self, *args, **kwargs):
        super(ColoredFormatter, self).__init__(*args, **kwargs)

    def format(self, record):
        line = super(ColoredFormatter, self).format(record)
        levelname = record.levelname
        if levelname in self.COLORS:
            line = self.COLORS[levelname] + line + self.COLORS_RESET
        return line


def logging_level(string):
    """Convert a string to a logging level"""
    if string.isnumeric():
        return int(string)
    level = getattr(logging, string.upper(), None)
    if not isinstance(level, int):
        raise argparse.ArgumentTypeError("invalid log level {}".format(string))
    return level


def main(argv=None):
    """Program entry point"""
    parser = argparse.ArgumentParser(description="Simple Python program")
    parser.add_argument('-c', '--color', action='store_true',
                        help="enable colors")
    parser.add_argument('-l', '--level', action='store',
                        type=logging_level, default=logging.INFO,
                        help="set logging level")

    group = parser.add_argument_group('format of logged message')
    group.add_argument('-p', '--pid', action='store_true',
                       help="log PID")
    group.add_argument('-s', '--shorttime', action='store_true',
                       help="print short time information")
    group.add_argument('-t', '--time', action='store_true',
                       help="print time information")
    group.add_argument('--default', action='store_true',
                       help="use default message format")

    group = parser.add_argument_group('level of logged message')
    group = group.add_mutually_exclusive_group()
    group.add_argument('-d', '--debug', dest='msglvl',
                       action='store_const', const=logging.DEBUG,
                       help="log message in debug level (suggest -lDEBUG too)")
    group.add_argument('-i', '--info', dest='msglvl',
                       action='store_const', const=logging.INFO,
                       help="log message in info level (default)")
    group.add_argument('-w', '--warning', dest='msglvl',
                       action='store_const', const=logging.WARNING,
                       help="log message in critical level")
    group.add_argument('-e', '--error', dest='msglvl',
                       action='store_const', const=logging.ERROR,
                       help="log message in error level")
    group.add_argument('-f', '--fatal', dest='msglvl',
                       action='store_const', const=logging.FATAL,
                       help="log message in critical level")

    args = parser.parse_args()

    logfmt = '[%(levelname)s] %(name)s: %(message)s'
    if args.pid:
        logfmt = '{}[{}]:'.format((argv or sys.argv)[0], os.getpid()) + logfmt
    if args.time or args.shorttime:
        logfmt = '%(asctime)s ' + logfmt
    datefmt = '%H:%M:%S' if args.shorttime else '%Y-%m-%d %H:%M:%S'

    if args.default:
        logging.basicConfig(level=args.level)
    elif args.color:
        log_handler = logging.StreamHandler()
        log_handler.setFormatter(
            ColoredFormatter(logfmt, datefmt=datefmt))
        root_logger = logging.getLogger()
        root_logger.addHandler(log_handler)
        root_logger.setLevel(args.level)
    else:
        logging.basicConfig(format=logfmt, level=args.level, datefmt=datefmt)

    if args.msglvl == logging.DEBUG:
        logger.debug("Hello, world!")
    elif args.msglvl == logging.WARNING:
        logger.warning("Hello, world!")
    elif args.msglvl == logging.ERROR:
        logger.error("Hello, world!")
    elif args.msglvl == logging.FATAL:
        logger.fatal("Hello, world!")
    else:
        logger.info("Hello, world!")


if __name__ == '__main__':
    sys.exit(main())
