/**
 * Record sound and play it back ("echo") using PulseAusio
 *
 * To suppress noise or echo effect, launch this program with:
 *
 *     PULSE_PROP='filter.want=echo-cancel' ./pulseaudio_echo.bin
 *
 * Documentation:
 * * http://www.freedesktop.org/wiki/Software/PulseAudio/Documentation/Developer/
 *
 * Examples:
 * * http://cgit.freedesktop.org/pulseaudio/pulseaudio/tree/src/tests/parec-simple.c
 * * http://cgit.freedesktop.org/pulseaudio/pulseaudio/tree/src/tests/pacat-simple.c
 * * http://cgit.freedesktop.org/pulseaudio/pulseaudio/tree/src/utils/pacat.c
 * * http://www.libsdl.org/release/SDL-1.2.15/src/audio/pulse/SDL_pulseaudio.c
 */
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

/* PulseAudio headers use "inline", which is not ISO C */
#ifndef inline
#    define inline __inline__
#endif

#include <pulse/pulseaudio.h>

/** Time period of the display of a status message */
#define STATUS_PERIOD_USEC 1000000

#define __unused __attribute__ ((unused))

/**
 * Global variables
 */
static pa_mainloop_api *g_mainloop_api;
static pa_context *g_context;
static pa_stream *g_stream_in, *g_stream_out;
static size_t g_bytes_read, g_bytes_written;

/**
 * Get a string describing the audio stream
 */
static const char *stream_name(const pa_stream *s)
{
    if (s == g_stream_in) {
        return "RECORD";
    } else if (s == g_stream_out) {
        return "PLAYBACK";
    }
    return "UNKNOWN";
}

static void signal_quit_cb(
    pa_mainloop_api *mainloop_api, pa_signal_event *s __unused,
    int sig, void *userdata __unused)
{
    assert(mainloop_api && mainloop_api == g_mainloop_api);
    fprintf(stderr, "Received signal %d, exiting\n", sig);
    mainloop_api->quit(mainloop_api, 0);
}

/**
 * Forward data from g_stream_in to g_stream_out
 */
static void forward_in_out(size_t arg_length_in, size_t arg_length_out)
{
    static void *s_buffer;
    static size_t s_bufferlen;
    size_t length_in, length_out, length;
    const void *data;
    void *new_buffer;
    int error;

    /* Compute the length of input and input */
    length_in = pa_stream_readable_size(g_stream_in);
    length_out = pa_stream_writable_size(g_stream_out);
    assert(length_in != (size_t)-1);
    assert(length_out != (size_t)-1);
    assert(!arg_length_in || arg_length_in == length_in);
    assert(!arg_length_out || arg_length_out == length_out);

    /* Read data */
    if (length_in > 0) {
        length = length_in;
        if (pa_stream_peek(g_stream_in, &data, &length) < 0) {
            error = pa_context_errno(pa_stream_get_context(g_stream_in));
            fprintf(stderr, "pa_stream_peek: %s\n", pa_strerror(error));
            g_mainloop_api->quit(g_mainloop_api, 1);
            return;
        }
        assert(data);
        assert(length > 0 && length == length_in);

        /* Add the data to the buffer */
        if (s_buffer) {
            s_buffer = pa_xrealloc(s_buffer, s_bufferlen + length);
            memcpy((uint8_t *)s_buffer + s_bufferlen, data, length);
            s_bufferlen += length;
        } else {
            s_buffer = pa_xmalloc(length);
            memcpy(s_buffer, data, length);
            s_bufferlen = length;
        }

        /* Drop input fragment */
        pa_stream_drop(g_stream_in);
        g_bytes_read += length;
    }

    /* Write data to the output */
    length = (length_out < s_bufferlen) ? length_out : s_bufferlen;
    if (length > 0) {
        assert(s_buffer);
        if (pa_stream_write(g_stream_out, s_buffer, length, NULL, 0, PA_SEEK_RELATIVE) < 0) {
            error = pa_context_errno(pa_stream_get_context(g_stream_out));
            fprintf(stderr, "pa_stream_write: %s\n", pa_strerror(error));
            g_mainloop_api->quit(g_mainloop_api, 1);
            return;
        }
        g_bytes_written += length;

        /* Shift buffer */
        new_buffer = NULL;
        length = s_bufferlen - length;
        if (length > 0) {
            assert(length_out + length == s_bufferlen);
            new_buffer = pa_xmalloc(length);
            memcpy(new_buffer, (uint8_t *)s_buffer + length_out, length);
        }
        s_bufferlen = length;
        pa_xfree(s_buffer);
        s_buffer = new_buffer;
    }
}

static void stream_in_read_cb(pa_stream *s, size_t length, void *u __unused)
{
    assert(s && s == g_stream_in);
    assert(length > 0);
    if (g_stream_out) {
        forward_in_out(length, 0);
    }
}

static void stream_out_write_cb(pa_stream *s, size_t length, void *u __unused)
{
    assert(s && s == g_stream_out);
    assert(length > 0);
    if (g_stream_in) {
        forward_in_out(0, length);
    }
}

static void stream_suspended_cb(pa_stream *s, void *u __unused)
{
    assert(s);

    fprintf(stderr, "[INFO] Stream %s %s\n", stream_name(s),
            pa_stream_is_suspended(s) ? "suspended" : "resumed");
}

static void stream_underflow_cb(pa_stream *s, void *u __unused)
{
    assert(s);

    fprintf(stderr, "[INFO] Stream %s underflow\n", stream_name(s));
}

static void stream_overflow_cb(pa_stream *s, void *u __unused)
{
    assert(s);

    fprintf(stderr, "[INFO] Stream %s overflow\n", stream_name(s));
}

static void stream_started_cb(pa_stream *s, void *u __unused)
{
    assert(s);

    fprintf(stderr, "[INFO] Stream %s started\n", stream_name(s));
}

static void stream_moved_cb(pa_stream *s, void *u __unused)
{
    assert(s);

    fprintf(stderr, "[INFO] Stream %s moved to device %u (%s)\n",
            stream_name(s),
            pa_stream_get_device_index(s),
            pa_stream_get_device_name(s));
}

static void stream_buffer_attr_cb(pa_stream *s, void *u __unused)
{
    assert(s);

    fprintf(stderr, "[INFO] Stream %s buffer attributes changed\n", stream_name(s));
}

static void stream_event_cb(pa_stream *s, const char *name, pa_proplist *pl, void *u __unused)
{
    char *proptext;

    assert(s);
    assert(name);
    assert(pl);

    proptext = pa_proplist_to_string_sep(pl, ", ");
    fprintf(stderr, "[INFO] Stream %s event '%s', properties '%s'\n",
            stream_name(s), name, proptext);
    pa_xfree(proptext);
}

static void stream_update_timing_cb(pa_stream *s, int success, void *u __unused)
{
    static pa_usec_t s_last_usec_in, s_last_usec_out;
    static size_t s_last_bytes_read, s_last_bytes_written;
    pa_usec_t latency = 0, usec = 0;
    int negative = 0, error;
    double byterate;

    assert(s);

    if (!success ||
        pa_stream_get_time(s, &usec) < 0 ||
        pa_stream_get_latency(s, &latency, &negative) < 0) {
        error = pa_context_errno(pa_stream_get_context(s));
        fprintf(stderr, "stream_update_timing: %s\n", pa_strerror(error));
        g_mainloop_api->quit(g_mainloop_api, 1);
        return;
    }

    if (s == g_stream_in) {
        if (usec > s_last_usec_in) {
            byterate = PA_USEC_PER_SEC *
                (double)(g_bytes_read - s_last_bytes_read) / (double)(usec - s_last_usec_in);
        } else {
            byterate = 0;
        }
        fprintf(stderr, "Recorded %10.2f Bps               latency %5.0f usec\n",
                byterate, (double)(negative ? -latency : latency));
        s_last_usec_in = usec;
        s_last_bytes_read = g_bytes_read;
    } else if (s == g_stream_out) {
        if (usec > s_last_usec_out) {
            byterate = PA_USEC_PER_SEC *
                (double)(g_bytes_written - s_last_bytes_written) / (double)(usec - s_last_usec_out);
        } else {
            byterate = 0;
        }
        fprintf(stderr, " Played                %10.2f Bps latency            %7.0f usec\n",
                byterate, (double)(negative ? -latency : latency));
        s_last_usec_out = usec;
        s_last_bytes_written = g_bytes_written;
    }
}

static void te_show_status_cb(
    pa_mainloop_api *m, pa_time_event *e, const struct timeval *tv __unused, void *u __unused)
{
    pa_operation *o;
    int error;

    assert(m == g_mainloop_api);

    if (g_stream_in && pa_stream_get_state(g_stream_in) == PA_STREAM_READY) {
        o = pa_stream_update_timing_info(g_stream_in, stream_update_timing_cb, NULL);
        if (!o) {
            error = pa_context_errno(pa_stream_get_context(g_stream_in));
            fprintf(stderr, "pa_stream_update_timing_info(in): %s\n", pa_strerror(error));
            g_mainloop_api->quit(g_mainloop_api, 1);
            return;
        }
        pa_operation_unref(o);
    }
    if (g_stream_out && pa_stream_get_state(g_stream_out) == PA_STREAM_READY) {
        o = pa_stream_update_timing_info(g_stream_out, stream_update_timing_cb, NULL);
        if (!o) {
            error = pa_context_errno(pa_stream_get_context(g_stream_out));
            fprintf(stderr, "pa_stream_update_timing_info(out): %s\n", pa_strerror(error));
            g_mainloop_api->quit(g_mainloop_api, 1);
            return;
        }
        pa_operation_unref(o);
    }

    pa_context_rttime_restart(g_context, e, pa_rtclock_now() + STATUS_PERIOD_USEC);
}

int main(void)
{
    int retval = 0, error;

    pa_mainloop *mainloop;
    pa_context_state_t cstate;
    pa_stream_state_t sstate;
    pa_time_event *time_event;
    pa_stream_flags_t flags = (pa_stream_flags_t)(
        PA_STREAM_INTERPOLATE_TIMING |
        PA_STREAM_ADJUST_LATENCY |
        PA_STREAM_AUTO_TIMING_UPDATE);

    const pa_sample_spec sample_spec = {
        .format = PA_SAMPLE_S16LE,
        .rate = 44100,
        .channels = 2,
    };

    /* Have 1 second of latency */
    uint32_t latency = (uint32_t)pa_usec_to_bytes(PA_USEC_PER_SEC, &sample_spec);
    const pa_buffer_attr buffer_attr = {
        .tlength = latency,
        .minreq = 0,
        .maxlength = (uint32_t)-1,
        .prebuf = (uint32_t)-1,
        .fragsize = latency,
    };

    /* Create a mainloop */
    mainloop = pa_mainloop_new();
    if (!mainloop) {
        fprintf(stderr, "pa_mainloop_new failed\n");
        return 1;
    }
    g_mainloop_api = pa_mainloop_get_api(mainloop);
    assert(g_mainloop_api);
    pa_signal_new(SIGINT, signal_quit_cb, NULL);
    pa_signal_new(SIGTERM, signal_quit_cb, NULL);

    /* Set-up signal handling */
    if (pa_signal_init(g_mainloop_api) < 0) {
        fprintf(stderr, "pa_context_init failed\n");
        return 1;
    }

    /* Create a context */
    g_context = pa_context_new(g_mainloop_api, "PA Echo");
    if (!g_context) {
        fprintf(stderr, "pa_context_new failed\n");
        return 1;
    }

    /* Connect to the default PulseAudio server */
    error = pa_context_connect(g_context, NULL, 0, NULL);
    if (error < 0) {
        assert(error == -pa_context_errno(g_context));
        fprintf(stderr, "pa_context_connect: %s\n", pa_strerror(-error));
        return 1;
    }
    do {
        if (pa_mainloop_iterate(mainloop, 1, NULL) < 0) {
            fprintf(stderr, "pa_mainloop_iterate failed\n");
            return 1;
        }
        cstate = pa_context_get_state(g_context);
        if (!PA_CONTEXT_IS_GOOD(cstate)) {
            fprintf(stderr, "Failed to connect to PulseAudio\n");
            return 1;
        }
    } while (cstate != PA_CONTEXT_READY);
    printf("Connection to PulseAudio established.\n");

    /* Create playback stream */
    g_stream_out = pa_stream_new(g_context, "PA Echo Playback", &sample_spec, NULL);
    if (!g_stream_out) {
        error = pa_context_errno(g_context);
        fprintf(stderr, "pa_stream_new(playback): %s\n", pa_strerror(error));
        return 1;
    }
    pa_stream_set_write_callback(g_stream_out, stream_out_write_cb, NULL);
    pa_stream_set_suspended_callback(g_stream_out, stream_suspended_cb, NULL);
    pa_stream_set_underflow_callback(g_stream_out, stream_underflow_cb, NULL);
    pa_stream_set_overflow_callback(g_stream_out, stream_overflow_cb, NULL);
    pa_stream_set_started_callback(g_stream_out, stream_started_cb, NULL);
    pa_stream_set_moved_callback(g_stream_out, stream_moved_cb, NULL);
    pa_stream_set_buffer_attr_callback(g_stream_out, stream_buffer_attr_cb, NULL);
    pa_stream_set_event_callback(g_stream_out, stream_event_cb, NULL);
    error = pa_stream_connect_playback(g_stream_out, NULL, &buffer_attr, flags, NULL, NULL);
    if (error < 0) {
        assert(error == -pa_context_errno(g_context));
        fprintf(stderr, "pa_stream_connect_playback: %s\n", pa_strerror(-error));
        return 1;
    }
    do {
        if (pa_mainloop_iterate(mainloop, 1, NULL) < 0) {
            fprintf(stderr, "pa_mainloop_iterate failed\n");
            return 1;
        }
        sstate = pa_stream_get_state(g_stream_out);
        if (!PA_STREAM_IS_GOOD(sstate)) {
            error = pa_context_errno(g_context);
            fprintf(stderr, "Failed to create playback stream: %s\n", pa_strerror(error));
            return 1;
        }
    } while (sstate != PA_STREAM_READY);
    printf("Record and playback streams are ready.\n");

    /* Create record stream */
    g_stream_in = pa_stream_new(g_context, "PA Echo Record", &sample_spec, NULL);
    if (!g_stream_in) {
        error = pa_context_errno(g_context);
        fprintf(stderr, "pa_stream_new(record): %s\n", pa_strerror(error));
        return 1;
    }
    pa_stream_set_read_callback(g_stream_in, stream_in_read_cb, NULL);
    pa_stream_set_suspended_callback(g_stream_in, stream_suspended_cb, NULL);
    pa_stream_set_underflow_callback(g_stream_in, stream_underflow_cb, NULL);
    pa_stream_set_overflow_callback(g_stream_in, stream_overflow_cb, NULL);
    pa_stream_set_started_callback(g_stream_in, stream_started_cb, NULL);
    pa_stream_set_moved_callback(g_stream_in, stream_moved_cb, NULL);
    pa_stream_set_buffer_attr_callback(g_stream_in, stream_buffer_attr_cb, NULL);
    pa_stream_set_event_callback(g_stream_in, stream_event_cb, NULL);
    error = pa_stream_connect_record(g_stream_in, NULL, &buffer_attr, flags);
    if (error < 0) {
        assert(error == -pa_context_errno(g_context));
        fprintf(stderr, "pa_stream_connect_record: %s\n", pa_strerror(-error));
        return 1;
    }
    do {
        if (pa_mainloop_iterate(mainloop, 1, NULL) < 0) {
            fprintf(stderr, "pa_mainloop_iterate failed\n");
            return 1;
        }
        sstate = pa_stream_get_state(g_stream_in);
        if (!PA_STREAM_IS_GOOD(sstate)) {
            error = pa_context_errno(g_context);
            fprintf(stderr, "Failed to create record stream: %s\n", pa_strerror(error));
            return 1;
        }
    } while (sstate != PA_STREAM_READY);

    /* Display statistics every second */
    time_event = pa_context_rttime_new(
        g_context, pa_rtclock_now() + STATUS_PERIOD_USEC, te_show_status_cb, NULL);
    if (!time_event) {
        fprintf(stderr, "time_event failed\n");
        return 1;
    }

    /* Launch the main loop */
    error = pa_mainloop_run(mainloop, &retval);
    if (error < 0) {
        fprintf(stderr, "pa_mainloop_run: %s\n", pa_strerror(error));
        retval = 1;
    }

    /* Destroy everything */
    g_mainloop_api->time_free(time_event);
    pa_stream_unref(g_stream_out);
    pa_stream_unref(g_stream_in);
    pa_context_disconnect(g_context);
    pa_context_unref(g_context);
    pa_signal_done();
    pa_mainloop_free(mainloop);
    return retval;
}
