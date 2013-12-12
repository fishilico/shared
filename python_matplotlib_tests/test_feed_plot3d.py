#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2013 Nicolas Iooss
#
# Everyone is permitted to copy and distribute verbatim or modified
# copies of this license document, and changing it is allowed as long
# as the name is changed.
#
#            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
#   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
#
#  0. You just DO WHAT THE FUCK YOU WANT TO.
"""
Test matplotlib's plot3d with a flowing data feed

@author: Nicolas Iooss
@license: WTFPL
"""

import argparse
import logging
from matplotlib import pyplot
from mpl_toolkits.mplot3d import Axes3D
import matplotlib.animation as animation
import numpy
import time
import threading


logger = logging.getLogger(__name__)

METHOD_ANIMATE = 'method:animate'
METHOD_THREAD = 'method:thread'


def randomwalk(n=50, sigma=0.02, alpha=0.95, seed=1):
    """ A simple random walk with memory

    This piece of code comes from
    http://stackoverflow.com/questions/11874767/real-time-plotting-in-while-loop-with-matplotlib
    """
    gen = numpy.random.RandomState(seed)
    pos = gen.rand(3, n)
    old_delta = gen.randn(3, n) * sigma
    while True:
        delta = (1. - alpha) * gen.randn(3, n) * sigma + alpha * old_delta
        pos += delta
        for i in range(n):
            if not (0. <= pos[0, i] < 1):
                pos[0, i] = abs(pos[0, i] % 1)
            if not (0. <= pos[1, i] < 1):
                pos[1, i] = abs(pos[1, i] % 1)
            if not (0. <= pos[2, i] < 1):
                pos[2, i] = abs(pos[2, i] % 1)
        old_delta = delta
        yield pos


def log_fps(frames, timediff):
    """Print FPS with a reasonable amount of time between each message"""
    if timediff < 1 or frames == 0 or (frames % 100) != 0:
        return
    # Print message each 1000 frame if FPS > 100
    if frames > 100 * timediff and (frames % 1000) != 0:
        return
    logger.info('Frame {:6d}: FPS {}'.format(frames, int(frames / timediff)))


class FeedPlot3d(object):

    def __init__(self, method, blit=False):
        self.blit = blit

        # Setup figure and axes
        self.fig = pyplot.figure()
        self.ax = Axes3D(self.fig)
        self.ax.set_xlabel('X')
        self.ax.set_ylabel('Y')
        self.ax.set_zlabel('Z')
        self.ax.set_title('3D Test')
        self.ax.set_aspect('equal')
        self.ax.set_xlim3d([0, 1])
        self.ax.set_ylim3d([0, 1])
        self.ax.set_zlim3d([0, 1])
        self.ax.hold(True)

        # Start random walk
        self.rw = randomwalk()
        x, y, z = next(self.rw)
        self.plt = self.ax.plot(x, y, z, 'o')[0]

        if method == METHOD_ANIMATE:
            # Setup animation
            logger.debug("Use animation method")
            self.anim = animation.FuncAnimation(
                self.fig, self._animate_update_plot,
                fargs=(self.rw, self.plt, [0]),
                interval=1, blit=blit)
        elif method == METHOD_THREAD:
            # Start computing thread
            logger.debug("Use thread method")
            thread = threading.Thread(target=self._computing_thread)
            thread.daemon = True
            thread.start()
        else:
            raise Exception("Unkown method {}".format(method))

    @staticmethod
    def _animate_update_plot(iframe, rw, plt, start_tic_ptr):
        """animation callback to draw the plot"""
        if iframe == 0:
            start_tic_ptr[0] = time.time()
        else:
            log_fps(iframe, time.time() - start_tic_ptr[0])
        x, y, z = next(rw)
        plt.set_data(x, y)
        plt.set_3d_properties(z)
        return [plt]

    def _computing_thread(self):
        # Only redraw background once per second
        background = None
        bkg_tic = None
        start_tic = time.time()
        iframe = 0
        while True:
            tic = time.time()
            iframe += 1
            x, y, z = next(self.rw)
            self.plt.set_data(x, y)
            self.plt.set_3d_properties(z)
            if not self.blit:
                self.fig.canvas.draw()
            elif not self.blit or background is None or bkg_tic + 0.5 <= tic:
                # Basic drawing and cache the background
                self.plt.set_visible(False)
                self.fig.canvas.draw()
                self.plt.set_visible(True)
                background = self.fig.canvas.copy_from_bbox(self.ax.bbox)
                self.fig.canvas.draw()
                bkg_tic = tic
            else:
                # Use blit/partial redrawing
                self.fig.canvas.restore_region(background)
            self.ax.draw_artist(self.plt)
            self.fig.canvas.blit(self.ax.bbox)
            log_fps(iframe, tic - start_tic)

    def loop(self):
        """Blocking main loop"""
        pyplot.show(block=True)


def main(argv=None):
    """Entry point"""
    parser = argparse.ArgumentParser(
        description="Test matplotlib's plot3d with a flowing data feed")
    parser.add_argument(
        '-a', '--animate', dest='method', action='store_const',
        const=METHOD_ANIMATE,
        help="use matplotlib.animation method")
    parser.add_argument(
        '-t', '--thread', dest='method', action='store_const',
        const=METHOD_THREAD,
        help="use thread method")
    parser.add_argument(
        '-b', '--blit', dest='blit', action='store_const',
        const=True, default=False,
        help="enable blit")

    args = parser.parse_args(argv)
    obj = FeedPlot3d(args.method or METHOD_THREAD, blit=args.blit)
    obj.loop()
    return 0


if __name__ == '__main__':
    import sys
    logging.basicConfig(format='[%(levelname)5s] %(name)s: %(message)s',
                        level=logging.DEBUG)
    sys.exit(main())
