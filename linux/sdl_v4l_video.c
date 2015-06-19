/**
 * Capture a video using V4L (Video for Linux) module and SDL to display
 */
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

#include <SDL/SDL.h>

#define NB_BUFFER 4

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
    if (ioctl(fd, VIDIOC_QUERYCAP, &cap) < 0) {
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
    if (ioctl(fd, VIDIOC_S_FMT, &fmt) < 0) {
        perror("ioctl(VIDIOC_S_FMT)");
        capture_stop(capst);
        return false;
    }

    /* Set streaming parameters (FPS) */
    memset(&setfps, 0, sizeof(struct v4l2_streamparm));
    setfps.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    setfps.parm.capture.timeperframe.numerator = 1;
    setfps.parm.capture.timeperframe.denominator = capture_frame_rate;
    if (ioctl(fd, VIDIOC_S_PARM, &setfps) < 0) {
        perror("ioctl(VIDIOC_S_PARM)");
        capture_stop(capst);
        return false;
    }

    /* Request MemoryMapping with NB_BUFFER buffers */
    memset(&rb, 0, sizeof(struct v4l2_requestbuffers));
    rb.count = NB_BUFFER;
    rb.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    rb.memory = V4L2_MEMORY_MMAP;
    if (ioctl(fd, VIDIOC_REQBUFS, &rb) < 0) {
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
        if (ioctl(fd, VIDIOC_QUERYBUF, &buf) < 0) {
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
        if (ioctl(fd, VIDIOC_QBUF, &buf) < 0) {
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
    if (ioctl(capst->fd, VIDIOC_DQBUF, &buf) < 0) {
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
    if (ioctl(capst->fd, VIDIOC_QBUF, &buf) < 0) {
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
    int result;
    char driver_name[128];
    void *uyvy_frame;
    struct capture_state capst;
    unsigned int video_format = SDL_ANYFORMAT | SDL_DOUBLEBUF | SDL_RESIZABLE;
    SDL_Rect screen_rect;
    SDL_Surface *screen;
    SDL_Overlay *overlay;
    SDL_Event event;
    struct timespec tv;
    time_t time_start;
    bool is_first_frame;

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
    SDL_WM_SetCaption("SDL V4L Test", NULL);
    SDL_VideoDriverName(driver_name, sizeof(driver_name));
    printf("Rendering using video driver '%s'\n", driver_name);
    screen = SDL_SetVideoMode(width, height, 0, video_format);
    overlay = SDL_CreateYUVOverlay(width, height, SDL_YV12_OVERLAY, screen);

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
                    printf("SDL_QUIT event received\n");
                    result = 0;
                    goto quit;

                case SDL_VIDEORESIZE:
                    screen = SDL_SetVideoMode(event.resize.w, event.resize.h, 0, video_format);
                    /* Don't support more than what SDL_Rect can handle */
                    resz_w = (event.resize.w > UINT16_MAX) ? UINT16_MAX : (uint16_t)event.resize.w;
                    resz_h = (event.resize.h > UINT16_MAX) ? UINT16_MAX : (uint16_t)event.resize.h;

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
                    break;

                case SDL_KEYDOWN:
                    if (event.key.keysym.sym == SDLK_q) {
                        /* Q quits */
                        post_sdlquit_event();
                    } else if (event.key.keysym.sym == SDLK_F11) {
                        /* F11 toggles fullscreen */
                        video_format ^= SDL_FULLSCREEN;
                        screen = SDL_SetVideoMode(0, 0, 0, video_format);
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
        SDL_LockYUVOverlay(overlay);
        uyvy2yv12(overlay->pixels[0], uyvy_frame, width, height);
        SDL_UnlockYUVOverlay(overlay);
        SDL_DisplayYUVOverlay(overlay, &screen_rect);
    }

quit:
    SDL_FreeYUVOverlay(overlay);
    SDL_Quit();
    capture_stop(&capst);
    free(uyvy_frame);
    return result;
}
