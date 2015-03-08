/**
 * Use POSIX message queues
 *
 * Documentation: http://man7.org/linux/man-pages/man7/mq_overview.7.html
 */
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE /* for NAME_MAX, stpcpy */
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mqueue.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define DEV_MQUEUE_PATH "/dev/mqueue"

static void dump_mqueue_state(const char *queue_name)
{
    char filename[sizeof(DEV_MQUEUE_PATH) + NAME_MAX];
    FILE *f;
    char buffer[4096];

    /* queue_name would be an acceptable name for mq_open,
     * but better be safe than sorry concerning memory */
    if (strlen(queue_name) > NAME_MAX) {
        printf("Queue name is too long to dump the queue.\n");
        return;
    }
    strcpy(stpcpy(filename, DEV_MQUEUE_PATH), queue_name);
    f = fopen(filename, "r");
    if (!f) {
        perror("fopen(/dev/mqueue/...)");
        return;
    }
    printf("Content of %s: ", filename);
    while (fgets(buffer, sizeof(buffer), f)) {
        fputs(buffer, stdout);
    }
    fclose(f);
}

int main(int argc, char **argv)
{
    mqd_t mqdes;
    const char *queue_name = "/test_message_queue";
    const char *message_text;
    char buffer[4096];
    struct mq_attr attr;
    ssize_t recv_size;
    unsigned int prio;
    int retval = 1;

    if (argc >= 2) {
        queue_name = argv[1];
    }

    /* Create a new message queue */
    attr.mq_flags = 0;
    attr.mq_maxmsg = 10;
    attr.mq_msgsize = sizeof(buffer);
    attr.mq_curmsgs = 0;
    mqdes = mq_open(queue_name, O_WRONLY | O_CREAT | O_EXCL, 0600, &attr);
    if (mqdes == (mqd_t)-1) {
        if (errno == ENOSYS) {
            fprintf(stderr, "Exit because the kernel does not support mq_open.\n");
            exit(0);
        }
        perror("mq_open");
        if (queue_name[0] != '/') {
            fprintf(stderr, "It seems that the initial '/' is missing.\n");
        }
        return 1;
    }

    /* Send a message */
    message_text = "Hello, world!";
    if (mq_send(mqdes, message_text, strlen(message_text), 1) == -1) {
        perror("mq_send");
        goto cleanup;
    }
    message_text = "The answer is 42.";
    if (mq_send(mqdes, message_text, strlen(message_text), 42) == -1) {
        perror("mq_send");
        goto cleanup;
    }
    mq_close(mqdes);
    mqdes = (mqd_t)-1;

    /* Dump current mqueue state */
    dump_mqueue_state(queue_name);

    /* Re-open the queue and read the message */
    mqdes = mq_open(queue_name, O_RDONLY | O_NONBLOCK);
    if (mqdes == (mqd_t)-1) {
        perror("mq_open");
        goto cleanup;
    }
    if (mq_getattr(mqdes, &attr) == -1) {
        perror("mq_getattr");
        goto cleanup;
    }
    assert((size_t)attr.mq_msgsize <= sizeof(buffer));
    assert(attr.mq_curmsgs >= 0);
    if (attr.mq_curmsgs == 0) {
        printf("There is no message in the queue. It has disappeared!\n");
        goto cleanup;
    }
    while (--attr.mq_curmsgs >= 0) {
        recv_size = mq_receive(mqdes, buffer, (size_t)attr.mq_msgsize, &prio);
        if (recv_size == -1) {
            perror("mq_receive");
            goto cleanup;
        }
        assert(recv_size >= 0 && (size_t)recv_size < sizeof(buffer));
        buffer[recv_size] = '\0';
        printf("Received message with prio %u: %s\n", prio, buffer);
    }
    retval = 0;
cleanup:
    if (mqdes != (mqd_t)-1) {
        mq_close(mqdes);
    }
    mq_unlink(queue_name);
    return retval;
}
