/**
 * Capture a video using V4L (Video for Linux) module and SDL to display
 *
 * This is like:
 * * Running vlc v4l2:///dev/video0
 * * GNOME Cheese (https://wiki.gnome.org/Apps/Cheese)
 */
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE /* for clock_gettime, usleep */
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/videodev2.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <SDL2/SDL.h>

#define NB_BUFFER 4

/* musl uses POSIX specification for ioctl(int, int, ...) instead of glibc
 * ioctl(int, unsigned long, ...). This causes a -Woverflow to occur when
 * using read ioctl (because they have their most significant bit set).
 * Work around this by always casting the request to int when not using
 * glibc.
 */
#ifdef __GLIBC__
#    define ioctl_read(fd, req, ptr) ioctl((fd), (req), (ptr))
#else
#    define ioctl_read(fd, req, ptr) ioctl((fd), (int)(req), (ptr))
#endif

/**
 * Structure to store the capture state of V4L
 */
struct capture_state {
    unsigned int display_width;
    unsigned int display_height;
    unsigned int capture_frame_rate;

    int fd;
    void *mem[NB_BUFFER];
    size_t mem_size[NB_BUFFER];
};

/**
 * Stop a V4L capture
 */
static void capture_stop(struct capture_state *capst)
{
    unsigned int i;

    assert(capst);

    if (capst->fd >= 0) {
        int type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        /* This ioctl may fail is there has been a problem in start_capture */
        ioctl(capst->fd, VIDIOC_STREAMOFF, &type);
    }
    for (i = 0; i < NB_BUFFER; i++) {
        if (capst->mem_size[i] > 0 && capst->mem[i] != NULL) {
            if (capst->mem[i] != MAP_FAILED) {
                munmap(capst->mem[i], capst->mem_size[i]);
            }
            capst->mem_size[i] = 0;
            capst->mem[i] = NULL;
        }
    }
    if (capst->fd >= 0) {
        close(capst->fd);
        capst->fd = -1;
    }
}

/**
 * Start a V4L capture
 */
static bool capture_start(
    struct capture_state *capst,
    unsigned int display_width, unsigned int display_height,
    unsigned int capture_frame_rate)
{
    struct v4l2_capability cap;
    struct v4l2_format fmt;
    struct v4l2_streamparm setfps;
    struct v4l2_requestbuffers rb;
    unsigned int i;
    int fd, type;

    assert(capst);
    memset(capst, 0, sizeof(struct capture_state));
    capst->display_width = display_width;
    capst->display_height = display_height;
    capst->capture_frame_rate = capture_frame_rate;

    /* Open the video device */
    fd = open("/dev/video0", O_RDWR | O_NONBLOCK);
    capst->fd = fd;
    if (fd < 0) {
        perror("open(/dev/video0)");
        return false;
    }

    /* Ask for the capabilities of the device */
    memset(&cap, 0, sizeof(struct v4l2_capability));
    if (ioctl_read(fd, VIDIOC_QUERYCAP, &cap) < 0) {
        perror("ioctl(VIDIOC_QUERYCAP)");
        capture_stop(capst);
        return false;
    }

    /* Set capture format (size and pixel format) */
    memset(&fmt, 0, sizeof(struct v4l2_format));
    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    fmt.fmt.pix.width = display_width;
    fmt.fmt.pix.height = display_height;
    fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_YUYV;
    fmt.fmt.pix.field = V4L2_FIELD_ANY;
    if (ioctl_read(fd, VIDIOC_S_FMT, &fmt) < 0) {
        perror("ioctl(VIDIOC_S_FMT)");
        capture_stop(capst);
        return false;
    }

    /* Set streaming parameters (FPS) */
    memset(&setfps, 0, sizeof(struct v4l2_streamparm));
    setfps.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    setfps.parm.capture.timeperframe.numerator = 1;
    setfps.parm.capture.timeperframe.denominator = capture_frame_rate;
    if (ioctl_read(fd, VIDIOC_S_PARM, &setfps) < 0) {
        perror("ioctl(VIDIOC_S_PARM)");
        capture_stop(capst);
        return false;
    }

    /* Request MemoryMapping with NB_BUFFER buffers */
    memset(&rb, 0, sizeof(struct v4l2_requestbuffers));
    rb.count = NB_BUFFER;
    rb.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    rb.memory = V4L2_MEMORY_MMAP;
    if (ioctl_read(fd, VIDIOC_REQBUFS, &rb) < 0) {
        perror("ioctl(VIDIOC_REQBUFS)");
        capture_stop(capst);
        return false;
    }

    /* Map the buffers */
    for (i = 0; i < NB_BUFFER; i++) {
        struct v4l2_buffer buf;
        memset(&buf, 0, sizeof(struct v4l2_buffer));
        buf.index = i;
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        if (ioctl_read(fd, VIDIOC_QUERYBUF, &buf) < 0) {
            perror("ioctl(VIDIOC_QUERYBUF)");
            capture_stop(capst);
            return false;
        }

        capst->mem[i] = mmap(0, buf.length, PROT_READ, MAP_SHARED, fd, (off_t)buf.m.offset);
        if (capst->mem[i] == MAP_FAILED) {
            perror("mmap(video buffer)");
            return false;
        }
        capst->mem_size[i] = buf.length;
    }

    /* Queue the buffers */
    for (i = 0; i < NB_BUFFER; ++i) {
        struct v4l2_buffer buf;
        memset(&buf, 0, sizeof(struct v4l2_buffer));
        buf.index = i;
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        if (ioctl_read(fd, VIDIOC_QBUF, &buf) < 0) {
            perror("ioctl(VIDIOC_QBUF)");
            capture_stop(capst);
            return false;
        }
    }

    /* Start streaming */
    type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (ioctl(fd, VIDIOC_STREAMON, &type) < 0) {
        perror("ioctl(VIDIOC_STREAMON)");
        capture_stop(capst);
        return false;
    }
    return true;
}

/**
 * Post a SDL quit event
 */
static void post_sdlquit_event(void)
{
    SDL_Event quit_event;

    memset(&quit_event, 0, sizeof(SDL_Event));
    quit_event.type = SDL_QUIT;
    SDL_PushEvent(&quit_event);
}

/**
 * Get a frame from a V4L capture in UYVY format
 */
static bool capture_get_frame(struct capture_state *capst, void *uyvy_frame)
{
    struct v4l2_buffer buf;
    uint32_t frame_size;
    bool ret = true;

    assert(capst && capst->fd != -1 && uyvy_frame);

    /* Get a frame if available */
    memset(&buf, 0, sizeof(struct v4l2_buffer));
    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP;
    if (ioctl_read(capst->fd, VIDIOC_DQBUF, &buf) < 0) {
        if (errno == EAGAIN) {
            /* Device is busy */
            return false;
        } else if (errno == ENODEV) {
            /* Quit nicely if the device is no longer here */
            printf("The video input device disappeared!\n");
            post_sdlquit_event();
            return false;
        }
        perror("ioctl(VIDIOC_DQBUF)");
        return false;
    }

    frame_size = capst->display_width * capst->display_height * 2;
    if (buf.bytesused < frame_size) {
        fprintf(stderr, "capture error: not enough data, %u < %u\n",
                buf.bytesused, frame_size);
        ret = false;
    } else {
        memcpy(uyvy_frame, capst->mem[buf.index], frame_size);
    }

    /* Put the buffer back */
    if (ioctl_read(capst->fd, VIDIOC_QBUF, &buf) < 0) {
        perror("ioctl(VIDIOC_QBUF)");
        return false;
    }
    return ret;
}

/**
 * Convert an image from UYVY to YV12
 */
static void uyvy2yv12(void *yv12, const void *uyvy, unsigned int w, unsigned int h)
{
    const unsigned int w2 = w / 2, h2 = h / 2;
    uint8_t *y = yv12;
    uint8_t *u = y + (w * h);
    uint8_t *v = u + (w2 * h2);
    const uint8_t *input = uyvy;
    unsigned int i, j;

    for (i = 0; i < h2; i++) {
        for (j = 0; j < w2; j++) {
            *y++ = input[0];
            *v++ = input[1];
            *y++ = input[2];
            *u++ = input[3];
            input += 4;
        }
        for (j = 0; j < w2; j++) {
            *y++ = input[0];
            *y++ = input[2];
            input += 4;
        }
    }
}

int main(void)
{
    uint16_t width, height, fps, resz_w, resz_h, new_w, new_h;
    int result, yv12_pitch;
    void *uyvy_frame, *yv12_pixels;
    struct capture_state capst;
    SDL_Rect screen_rect;
    SDL_Window *window;
    SDL_Renderer *renderer;
    SDL_Texture *texture;
    SDL_Event event;
    struct timespec tv;
    time_t time_start;
    bool is_first_frame;
    bool is_fullscreen = false;

    width = 640;
    height = 480;
    fps = 30;

    screen_rect.x = 0;
    screen_rect.y = 0;
    screen_rect.w = width;
    screen_rect.h = height;

    /* Setup SDL */
    result = SDL_Init(SDL_INIT_VIDEO);
    if (result < 0) {
        fprintf(stderr, "Could not start SDL (error %d)\n", result);
        return 1;
    }
    window = SDL_CreateWindow(
        "SDL V4L Test",
        SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
        width, height,
        SDL_WINDOW_RESIZABLE);
    if (!window) {
        fprintf(stderr, "Could not create window: %s\n", SDL_GetError());
        return 1;
    }
    renderer = SDL_CreateRenderer(window, -1, 0);
    if (!renderer) {
        fprintf(stderr, "Could not create renderer: %s\n", SDL_GetError());
        return 1;
    }
    texture = SDL_CreateTexture(
        renderer,
        SDL_PIXELFORMAT_YV12,
        SDL_TEXTUREACCESS_STREAMING,
        width, height);
    if (!texture) {
        fprintf(stderr, "Could not create texture: %s\n", SDL_GetError());
        return 1;
    }
    printf("Rendering using video driver '%s'\n", SDL_GetCurrentVideoDriver());

    /* Setup capture */
    uyvy_frame = malloc(width * height * 4);
    if (!uyvy_frame) {
        fprintf(stderr, "malloc() failed, out of memory\n");
        return 1;
    }
    if (!capture_start(&capst, width, height, fps)) {
        fprintf(stderr, "Unable to start video capture\n");
        return 1;
    }
    printf("Capture started with %u buffers\n", NB_BUFFER);

    /* Start timer */
    if (clock_gettime(CLOCK_MONOTONIC, &tv) == -1) {
        perror("clock_gettime(MONOTONIC)");
        result = 1;
        goto quit;
    }
    time_start = tv.tv_sec;
    is_first_frame = true;

    for (;;) {
        while (SDL_PollEvent(&event)) {
            switch (event.type) {
                case SDL_QUIT:
                    SDL_Log("SDL_QUIT event received");
                    result = 0;
                    goto quit;

                case SDL_WINDOWEVENT:
                    if (event.window.event == SDL_WINDOWEVENT_SIZE_CHANGED && event.window.windowID == SDL_GetWindowID(window)) {
                        /* SDL_Log("Window size changed to %dx%d", event.window.data1, event.window.data2); */

                        /* Don't support more than what SDL_Rect can handle */
                        resz_w = (event.window.data1 > UINT16_MAX) ? UINT16_MAX : (uint16_t)event.window.data1;
                        resz_h = (event.window.data2 > UINT16_MAX) ? UINT16_MAX : (uint16_t)event.window.data2;

                        /* Compute new size so that w/h is constant */
                        if (resz_w * height >= resz_h * width) {
                            new_h = resz_h;
                            new_w = width * new_h / height;
                        } else {
                            new_w = resz_w;
                            new_h = height * new_w / width;
                        }
                        screen_rect.x = (resz_w - new_w) / 2;
                        screen_rect.y = (resz_h - new_h) / 2;
                        screen_rect.w = new_w;
                        screen_rect.h = new_h;
                        SDL_RenderSetViewport(renderer, &screen_rect);
                    }
                    break;

                case SDL_KEYDOWN:
                    if (event.key.keysym.sym == SDLK_q) {
                        /* Q quits */
                        post_sdlquit_event();
                    } else if (event.key.keysym.sym == SDLK_f || event.key.keysym.sym == SDLK_F11) {
                        /* F and F11 toggles fullscreen */
                        result = SDL_SetWindowFullscreen(
                            window,
                            is_fullscreen ? 0 : SDL_WINDOW_FULLSCREEN_DESKTOP);
                        if (result < 0) {
                            SDL_LogError(
                                SDL_LOG_CATEGORY_APPLICATION,
                                "Unable to toggle fullscreen: %s",
                                SDL_GetError());
                            break;
                        }
                        is_fullscreen = !is_fullscreen;
                    }
                    break;
            }
        }

        /* Get frame */
        /* TODO: add a SDL timer instead of sleeping 1ms */
        if (!capture_get_frame(&capst, uyvy_frame)) {
            usleep(1000);
            continue;
        }

        if (is_first_frame) {
            is_first_frame = false;
            if (clock_gettime(CLOCK_MONOTONIC, &tv) == -1) {
                perror("clock_gettime(MONOTONIC)");
            } else if (tv.tv_sec != time_start) {
                printf("First frame after %ld second(s)\n", tv.tv_sec - time_start);
            }
        }
        /* Convert and display frame */
        yv12_pixels = NULL;
        SDL_LockTexture(texture, NULL, &yv12_pixels, &yv12_pitch);
        assert(yv12_pitch == width);
        uyvy2yv12(yv12_pixels, uyvy_frame, width, height);
        SDL_UnlockTexture(texture);

        SDL_RenderClear(renderer);
        SDL_RenderCopy(renderer, texture, NULL, NULL);
        SDL_RenderPresent(renderer);
    }

quit:
    SDL_DestroyTexture(texture);
    SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window);
    SDL_Quit();
    capture_stop(&capst);
    free(uyvy_frame);
    return result;
}
