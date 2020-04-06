# nfs_trace

An attempt to trace nfsv3 read requests on centos 6 (and probably 7 too)

**Using this in prod is not recommended, but if you do so let me know how it went**

# Internals

This "tracer" consists of two parts. A kernel module which "traces" the events
and provides a set of devices which user space can read. And a user space client
which prints them (like `tail -f` does).

## Kernel

Once loaded this module will create a device (`/dev/nfs_traceX`) for each CPU in
the system (hotplug not supported). Once a user `open(2)`s the device a `kprobe`
will be installed on the nfs read function which will extract the path from each
request and send it to a per cpu ring buffer. If no `consumer` has been
registered for the device (through `open`) the event will be dropped. If the
buffer is full the event will be dropped too.

Extracting data is done by `read(2)`ing data. Allowing the use of the standard
unix file handling, using both (`poll(2)` and `read(2)`). Both blocking and non-blocking
reads are supported.

Once the last consumer disconnects the kprobes are unregistered. This means
there will be no overhead when there are no consumers.
When there is no consumer for a cpu the overhead will be minimal. The kprobe
will still fire but will detect the lack of consumer before doing any serious work.

## User space

The user space application `open(2)`s all device and sets up a  `poll(2)`s and
`read(2)` loop, outputting events to stdout.

# Short comings / issues

- Can have only one consumer per device
- CPU hot plug is not supported
