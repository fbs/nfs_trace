#include <linux/string.h>
#include <linux/types.h>
#include <asm/uaccess.h>
#include "rkt_buf.h"

inline static unsigned int copy_in(char *dest, char const *source, unsigned int size)
{
    int errcount;
    errcount = copy_from_user(dest, source, size);
    if(errcount != 0) {
        printk(KERN_ALERT "Rocket echo: copy_to_user error!\n");
    }
    return (size - errcount);
}

inline static unsigned int copy_out(char *dest, char const *source, unsigned int size)
{
    int errcount;
    errcount = copy_to_user(dest, source, size);
    if(errcount != 0) {
        printk(KERN_ALERT "Rocket echo: copy_from_user error!\n");
    }
    return (size - errcount);
}

void rkt_buf_init(rkt_buf * ptr, char * buffer, unsigned int size)
{
    ptr->top = buffer;
    ptr->read_ptr = buffer;
    ptr->write_ptr = buffer;
    ptr->end = buffer + size;
}

unsigned int rkt_buf_level(rkt_buf *ptr)
{
    uintptr_t read_ptr = (uintptr_t) ptr->read_ptr;
    uintptr_t write_ptr = (uintptr_t) ptr->write_ptr;
    unsigned int level;

    if(write_ptr >= read_ptr) {
        level = (write_ptr - read_ptr);
    } else {
        level = ((write_ptr - (uintptr_t)ptr->top) + (uintptr_t)ptr->end) - read_ptr;
    }
    return level;
}

rkt_errcode rkt_buf_read(rkt_buf *ptr, char *target, unsigned int count)
{
    unsigned int remaining = count;
    unsigned int chunk;
    unsigned int buf_remaining;
    unsigned int transferred;
    rkt_errcode errcode = RKT_OK;

    while(remaining != 0) {
        buf_remaining = ptr->end - ptr->read_ptr;
        chunk = (buf_remaining <= remaining) ? buf_remaining : remaining;
        transferred = copy_out(target, ptr->read_ptr, chunk);

        if(transferred != chunk) {
            errcode = RKT_ERR;
            break;
        }

        remaining -= transferred;
        target += transferred;
        ptr->read_ptr += transferred;

        if(ptr->read_ptr >= ptr->end) {
            ptr->read_ptr = ptr->top;
        }
    }

    return errcode;
}

rkt_errcode rkt_buf_write(rkt_buf *ptr, char const * source, unsigned int count)
{
    unsigned int remaining = count;
    unsigned int chunk;
    unsigned int buf_remaining;
    unsigned int transferred;
    rkt_errcode errcode = RKT_OK;

    while(remaining != 0) {
        buf_remaining = ptr->end - ptr->write_ptr;
        chunk = (buf_remaining < remaining) ? buf_remaining : remaining;
        transferred = copy_in(ptr->write_ptr, source, chunk);

        if(transferred != chunk) {
            errcode = RKT_ERR;
            break;
        }

        remaining -= transferred;
        source += transferred;
        ptr->write_ptr += transferred;

        if(ptr->write_ptr >= ptr->end) {
            ptr->write_ptr = ptr->top;
        }
    }

    return errcode;
}
