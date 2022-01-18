pure ruby NSCA library
======================

NSCA is a protocol for Nagios passive checks.
You must run nsca on your server to use it.

This is a ruby-pure implementation.

First it was planed to provide a client-API, but now there is also a full server-API.

Tested against nsca-2.7, -2.9.

Usage
=====

Simple sending

```ruby
NSCA.destinations << NSCA::Client.new('localhost')
NSCA.send 'serverA', 'serviceA', 1, 'Ok'
```

TO DO AND DONE
==============

TODO
----

* server side parsing of performance data
* more documentations
* mcrypt-support

DONE
----

* packet-API (one check will be packed in one packet)
* simple-"encryption" (only xor with password and server-side generated iv-key)
* client-API (send to server)
* server-API (recv from client)
* check-API (describe checks and performance data)
* fast usable API for sending checks
* build packet with performance data

Copyright
=========

Copyright (c) 2013-2015 Denis Knauf. See [LICENSE.txt](LICENSE.txt) for further details.
