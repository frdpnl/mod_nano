# *mod\_nano*: a nanomsg Apache 2 module

### Introduction

*mod\_nano* translates HTTP requests into a request message for a [nanomsg][] [request/reply][reqrep] socket and the nanomsg reply into an HTTP response.

It passes the HTTP request and response as-is. It's a feature.

*mod\_nano* consists of a single source file (`mod_nano.c` :-), and only works under the *prefork* MPM.


[nanomsg]: http://nanomsg.org/ "nanomsg"
[reqrep]: http://nanomsg.org/v0.8/nn_reqrep.7.html "REQREP"

### Motivation

With nanomsg, you can decompose an application into several *parts*, which interact according to communication patterns.
nanomsg offers multiple communication patterns: request/reply, publish/subscribe, pipeline...  
The parts of an application are typically processes (but can also be threads), that run on possibly different machines (using the TCP transport), and can be programmed in different languages, see the [nanomsg documentation][nanomsgdoc].

With this simple module (and the nanomsg library), you can therefore implement message mediated microservices (as mentioned by [hackernews:tptacek][tptacek]), and benefit from message-passing application designs over a scalable, reliable network library.

*mod\_nano* uses [request/reply][reqrep] sockets, for several reasons:

- nanomsg request/reply match well (subjective :-) the semantics of HTTP, from the nanomsg request/reply RFC:
> [this RFC] defines a scalability protocol used for distributing
> processing tasks among arbitrary number of stateless processing nodes
> and returning the results of the processing.
- HTTP requests can be fully handled by a processing request/reply node.
  Yet, the processing node could also play the role of an entry point, forwarding the request 
  to a collection of other processing nodes (using other communication patterns, pipeline...) 
  and relaying the result back to the HTTP user-agent.
- simplicity.

[tptacek]: https://news.ycombinator.com/user?id=tptacek "tptacek"
[nanomsgdoc]: http://nanomsg.org/documentation.html "nanomsg documentation"

### Installation

There are two prerequisites: 

1.  the [nanomsg][] library, 
2.  [Apache 2][apache2] development files, on ubuntu package apache2-dev includes everything needed. 

Once these requirements are met, use the [apxs][] program:

		apxs -i -a -c mod_nano.c -lnanomsg

in the directory where `mod_nano.c` is.

[apache2]: https://httpd.apache.org/ "apache http server"
[apxs]: https://httpd.apache.org/docs/current/programs/apxs.html "APache eXtenSion Tool"

### Configuration

Some configuration is necessary to use the module.

The module defines a single directive: `nanoChannel`, which defines the endpoint for a nanomsg socket 
(it's called channel because endpoint could be misleading in an HTTP context).

Example configuration, which can be placed in a virtual host section:

		LogLevel info nano:debug

		<LocationMatch "^/api/">
			SetHandler nano-handler
			nanoChannel ipc:///tmp/ipc/default 1
		</LocationMatch>

		<LocationMatch "^/api/one$">
			nanoChannel ipc:///tmp/ipc/one-1
			nanoChannel ipc:///tmp/ipc/one-2
		</LocationMatch>

		<LocationMatch "^/api/two$">
			nanoChannel ipc:///tmp/ipc/two-1 1
		</LocationMatch>

This example says that:

- HTTP requests destined to /api/one are routed to a socket composed of two inter-process communication endpoints.
On POSIX systems, UNIX domain sockets are used for IPC.   
Why two endpoints? To distribute the load across two endpoints.
A process bound to the endpoint will get the message, and must reply.
If several processes bind to the _same_ endpoint, then they act as failover.
- HTTP requests destined to /api/two are routed to another socket composed of one endpoint.
- HTTP requests destined to /api/_something_ are routed to a default socket.

The numbers after the endpoints are the priorities. 
This is currently not implemented, but will be shortly because of it's benefits (failover to a remote site for instance).

Generally, [locations][locationdir] are appropriate, because channels can refer to TCP/IP sockets (IPC could be considered files).

[locationdir]: https://httpd.apache.org/docs/current/mod/core.html#locationmatch "Location directive"

### Programming

Once configured, some processes are needed to handle the forwarded requests.
Otherwise the HTTP user agent will wait for a while :-)

Multiple channels (endpoints, maybe I should just rename this...) are needed to distribute the load across listening processes.
But not all channels need to be listened to!
If more than one process listens to the same endpoint, then only one will handle requests.
However, in case of process termination, the other listening process will take over request handling.
This can make for non-stop software upgrades.
All of this is dynamic, meaning that new handling processes can be added, removed at runtime, and nanomsg will adjust.

As an example, `mod_nano_rep.c` binds to an endpoint/channel and replies with a HTTP message length.
You can start multiple of these to test (assuming `mod_nano_rep.c` builds to a `reply.out` executable):

		sudo -u www-data ./reply.out ipc:///tmp/ipc/one-1

can help test the setup (the `sudo` command is one way to ensure that the IPC file descriptor is accessible to both the `httpd` and the handling process).

*mod\_nano* can log debug messages (apache log) with much detail to provide HTTP header and body information.

