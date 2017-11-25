<img src="xtomp.png" style="float:right"/>

# xtomp

An in memory message broker that supports queues and topics and exposes a STOMP API.  
The message broker based on nginx platform using an event based approach that allows for very little overhead when nothing is going on on the server and the ability to handle many concurrent connections with a single process.

The core connection handling and event loop is provided by nginx. The STOMP protocol handling and in memory message storage and routing is implemented in C as a core module.

## features

* Low memory overhead.
* Low CPU usage when idle.
* memtop - in memory topic, (pub/sub)
* memq - queueing messages in memory.
* Subscription filters, enabling something akin to dynamically created topics.
* nginx connection handling allows hundreds of thousands of connections with a single process.


## utils

* xtomp-tap - Utility to connect to a STOMP server and echo messages to stdout, optionally delimited by a user defined separator.
* xtomp-sink - Utility to connect to a STOMP server and publish messages from stdin.
* xtomp-drain - Utility to empty messages from a queue.

# why xtomp?

I am using RabbitMQ via its STOMP API.
The default install uses comparatively large amount of RAM and CPU when the server is idle.  I was targeting micro instances in the cloud with 500MB of RAM total. I wanted an MQ server with a very low footprint.  Because STOMP is an open protocol its possible to rewrite the middleware without affecting the client or application code.

Due to being small and efficient I can also run xtomp on a Raspberry Pi.

ps aux on a Raspberry Pi

    USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
    teknopa+ 15252  0.0  0.2   2380  1064 ?        Ss   22:34   0:00 xtomp: master process /usr/local/xtomp/bin/xtomp
    teknopa+ 15253  0.0  0.2   2548  1220 ?        S    22:34   0:00 xtomp: worker process

ps aux on 64bit Ubuntu

    USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
    teknopa+ 17252  0.0  0.0   8992   220 ?        Ss   00:35   0:00 xtomp: master process /usr/local/xtomp/bin/xtomp
    teknopa+ 17253  0.0  0.0   9408  1552 ?        S    00:35   0:00 xtomp: worker process

& cos its fun writing code in nginx framework, its kinda like nodejs in C.

N.B.

xtomp is not precicelyu an nginx module, it can't be run inside a running nginx instance becasue it only supports a single process, nginx supports many.