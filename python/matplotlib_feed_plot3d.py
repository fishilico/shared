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
Test matplotlib's plot3d with a flowing data feed (using a random walk)

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
DRAW_PLOT = 'draw:plot'
DRAW_SCATTER = 'draw:scatter'
DEFAULT_COLOR = 'b'
DEFAULT_MARKER = 'o'


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
    """
    Create a 3D plot which simulate a feed of continuous data with a random
    walk
    """

    def __init__(self, method, blit=False, draw=None, color=None, marker=None):
        self.method = method
        self.blit = blit
        self.draw = draw or DRAW_SCATTER
        self.color = color or DEFAULT_COLOR
        self.marker = marker or DEFAULT_MARKER
        self.plt = None
        self.rw = randomwalk()

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

        logger.debug("Use {}, {}, {}".format(
            self.method, self.draw, "blit" if blit else "noblit"))

        if self.method == METHOD_ANIMATE:
            # Setup animation
            self.anim = animation.FuncAnimation(
                self.fig,
                self._animate_update_plot, fargs=([0],),
                init_func=self.setup_draw,
                interval=1, blit=self.blit)
        elif self.method == METHOD_THREAD:
            # Start computing thread
            self.setup_draw()
            thread = threading.Thread(target=self._computing_thread)
            thread.daemon = True
            thread.start()
        else:
            raise Exception("Unknown method {}".format(self.method))

    def setup_draw(self):
        """Setup the drawing"""
        if self.plt is None:
            if self.draw == DRAW_SCATTER:
                self.plt = self.ax.scatter(
                    [], [], [],
                    c=self.color, marker=self.marker,
                    animated=(self.method == METHOD_ANIMATE))
            elif self.draw == DRAW_PLOT:
                self.plt = self.ax.plot([], [], [], self.color + self.marker)[0]
            else:
                raise Exception("Unknown drawing {}".format(self.draw))
        return self.plt,

    def _animate_update_plot(self, iframe, start_tic_ptr):
        """animation callback to draw the plot"""
        if iframe == 0:
            start_tic_ptr[0] = time.time()
        else:
            log_fps(iframe, time.time() - start_tic_ptr[0])
        xyz = next(self.rw)
        if self.draw == DRAW_SCATTER:
            # 3D projection is overwriting 2D properties, which needs to be
            # reset before each drawing
            self.plt.set_alpha(1)
            self.plt.set_facecolors(self.color)
            self.plt.set_offsets(xyz[:2])
            self.plt.set_3d_properties(xyz[2], 'z')
            # Hack if blit is set: force 3D projection
            if self.blit:
                self.plt.do_3d_projection(self.ax.get_renderer_cache())
        elif self.draw == DRAW_PLOT:
            self.plt.set_data(xyz[:2])
            self.plt.set_3d_properties(xyz[2])
        return self.plt,

    def _computing_thread(self):
        """Entry point of the thread which draws the plot"""
        # Only redraw background once per second
        background = None
        bkg_tic = None
        start_tic = time.time()
        iframe = 0
        while True:
            tic = time.time()
            iframe += 1
            xyz = next(self.rw)
            if self.draw == DRAW_SCATTER:
                # Use mpl_toolkits.mplot3d.art3d.Patch3DCollection to
                # update everything. As do_3d_projection changes alpha and
                # offsets, they need to be reset beforehand.
                #
                # Note: self.plt.set_array(xyz[2]) may be used to only update
                #       z coordinates without changing (x, y)
                self.plt.set_alpha(1)
                self.plt.set_offsets(xyz[:2])
                self.plt.set_3d_properties(xyz[2], 'z')
            elif self.draw == DRAW_PLOT:
                self.plt.set_data(xyz[:2])
                self.plt.set_3d_properties(xyz[2])

            if not self.blit:
                self.fig.canvas.draw()
            else:
                if not self.blit or background is None or bkg_tic + 0.5 <= tic:
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

                # Blit drawing
                if self.draw == DRAW_SCATTER:
                    renderer = self.ax.get_renderer_cache()
                    self.plt.do_3d_projection(renderer)
                    self.plt.draw(renderer)
                else:
                    self.ax.draw_artist(self.plt)
                self.fig.canvas.blit(self.ax.bbox)
            log_fps(iframe, tic - start_tic)

    @staticmethod
    def loop():
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
        help="use thread method (default)")
    parser.add_argument(
        '-p', '--plot', dest='draw', action='store_const',
        const=DRAW_PLOT,
        help="draw points with plot (default)")
    parser.add_argument(
        '-s', '--scatter', dest='draw', action='store_const',
        const=DRAW_SCATTER,
        help="draw points with scatter")
    parser.add_argument(
        '-b', '--blit', dest='blit', action='store_const',
        const=True, default=False,
        help="enable blit")
    parser.add_argument(
        '-c', '--color', dest='color', action='store', type=str,
        help="color ('{}' by default)".format(DEFAULT_COLOR))
    parser.add_argument(
        '-m', '--marker', dest='marker', action='store', type=str,
        help="marker ('{}' by default)".format(DEFAULT_MARKER))

    args = parser.parse_args(argv)
    obj = FeedPlot3d(
        args.method or METHOD_THREAD,
        blit=args.blit,
        draw=args.draw or DRAW_PLOT,
        color=args.color,
        marker=args.marker)
    obj.loop()
    return 0


if __name__ == '__main__':
    import sys
    logging.basicConfig(format='[%(levelname)5s] %(name)s: %(message)s',
                        level=logging.DEBUG)
    sys.exit(main())
