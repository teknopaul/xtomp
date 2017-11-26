<img src="xtomp.png" style="float:right"/>

# xtomp

An in memory message broker that supports queues and topics and exposes a STOMP API.  
The message broker based on nginx platform using an event based approach that allows for very little overhead when nothing is going on on the server and the ability to handle many concurrent connections with a single process.

The core connection handling and event loop is provided by nginx. The STOMP protocol handling and in memory message storage and routing is implemented in C as a core module.

## features

* Low memory overhead.
* Low CPU usage when idle.
* In memory topic, (pub/sub)
* Queuing messages in memory.
* Subscription filters, enabling something akin to dynamically created topics.
* nginx connection handling allows hundreds of thousands of connections with a single process.

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

xtomp is not precisely an nginx module, it can't be run inside a running nginx instance because it only supports a single process, nginx supports many.

nginx is modular so xtomp is able to removes the HTTP, SMTP and streaming code in nginx to keep the size down.

## in memory

Xtomp does not disk IO in its normal operations, hopefully it should thus be obvious that it gives no delivery guarantees.  There is no concept of durable subscribers or durable topics in xtomp.  By default there is some I: logs and a pid file. By providing tmpfs space for the pid file and either tmpfs space for logging or using syslog its possible to run xtomp without writing any file at all, this is interesting in the case of the raspberry pi where typically commodity SD cards are used for storage so avoiding writes is important.