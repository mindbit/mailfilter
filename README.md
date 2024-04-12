Mailfilter
==========

Mailfilter is a Mail Transport Agent (MTA) framework with embedded JavaScript
support. The low-level part of the SMTP protocol, including the parsers, are
implemented in C, while the high-level logic is implemented in JavaScript. This
approach makes it easy to customize the behavior by changing the JavaScript
code, and without requiring to rebuild the C code.

Thanks to its hybrid design, Mailfilter does not hard-code any specific behavior
and can be used for a variety of applications, including a simple mail exchange
server. However, it was created with a very specific application in mind: to act
as a transparent/reverse SMTP proxy, sitting between the internet and a real SMTP
server, and to filter unsolicited and/or potentially harmful e-mail.

# Features

* Embedded JavaScript support (using [Duktape](http://duktape.org/))
* Basic SMTP/ESMTP protocol support (server and client)
* SPF support with JS API (using libspf2)
* Basic RBL support with JS API (DNS support using the system resolver)

# Typical setup

When used as a transparent/reverse SMTP proxy to filter e-mail, Mailfitler sits
between the internet and the real SMTP server. Typically, Mailfilter is used
only for incoming e-mail (relay), and the assumption is that outgoing e-mail
(mail submission) is only accepted with proper authentication and is therefore
legit and doesn't need to be filtered.

To support this configuration, the real SMTP server must use a separate port for
mail submission. This is always a good idea for various other reasons, such as:
* Port 25 is blocked for residential users by most ISPs.
* SMTP authentication can be disabled altogether on port 25. This reduces the
  surface of brute force attack on passwords, since most attackers use port 25.

In this scenario, the mail submission port (typically 587) is forwarded directly
to the real SMTP server, and Mailfilter intercepts only the relay port (25).

<b>Since the real SMTP server receives all relay mail from Mailfilter, the IP
addresses must be set up in such a way that the real SMTP server does NOT
consider Mailfilter's IP address a trusted IP address, or else this will turn
into an open relay configuration. This is particularly important when Mailfilter
and the real SMTP server run on the same machine, since 127.0.0.1 is a trusted
IP address in most configurations.</b>

There could be use cases for scanning outgoing e-mail, for example to check for
viruses or, in case junk e-mail is identified, for compromised clients. In that
case, Mailfilter would also intercept the mail submission path and sit between
the clients and the real SMTP server. However, this would require proxy support
for SMTP authentication, and it hasn't been implemented yet.

# Building and running

See [INSTALL.md](docs/INSTALL.md) for details on how to build and install
Mailfilter.

# Embedded JavaScript overview

The standard JavaScript environment is overloaded with additional objects and
"classes" to model an SMTP server, an SMTP client and various other SMTP
specific data structures such as headers and paths. These are conceptually
similar to the `document` and `window` objects in a browser JavaScript
environment.

Mailfilter starts by loading and running a JavaScript file, which serves as both
configuration (for example the SMTP bind address and port) and high-level logic
implementation. The SMTP related "classes" are created before the JavaScript
file is loaded, giving it the opportunity to overwrite some of the "methods".
Overwriting the SmtpServer "class methods" is the standard way of implementing
the high-level logic of the SMTP server.

After the JavaScript file is loaded, Mailfilter starts listening for incoming
SMTP connections. When a new connection is made, a separate process is forked to
handle the connection. Therefore, the JavaScript environment is completely
isolated from the other connections.

When a worked process is started as described above, a SmtpServer instance is
created automatically. The low-level logic of the SMTP protocol is built into
the Mailfilter engine, and various properties of the SmtpServer instance are
populated automatically, such as headers, the envelope sender, recipient
addresses etc. At each stage of the SMTP transaction (basically for each SMTP
verb), a corresponding "method" of the SmtpServer instance is called in the
JavaScript environment. The high-level logic/behavior can be customized by
overwriting these "methods" in the SmtpServer prototype, using the configuration
file.

SMTP protocol violations (such as syntax errors or using inappropriate verbs in
the current transaction state) are handled inside the Mailfilter engine, and a
reply is sent back to the client without calling the JavaScript handler.
However, if no such low-level SMTP protocol violations occur and the JavaScript
handler does get called, it can still send an error back to the client. In fact,
most JavaScript handlers are required to generate a response (status code and
message) to send back to the client.

The proxy application described above is implemented by creating an SmtpClient
instance (and a connection to the real SMTP server) early, in the initialization
phase of the SMTP transaction. Then, each JavaScript SMTP handler uses the
SmtpClient instance to send a command to the real SMTP server and read back the
response. Finally, the response is used as return value from the JavaScript SMTP
handler and passed back to the Mailfilter SMTP server engine.

# Relevance

Back in 2009 when the project was started, many organizations were still running
their own dedicated mail exchange, often on-premises. At that time it made sense
to create a unified mail filtering solution that was agnostic of the software
running on the mail exchange server and, more importantly, could be deployed
easily and without requiring configuration changes to the mail exchange server.

Fast-forward to the present, most organizations use cloud services such as Gmail
or Outlook to host their e-mail. These services already have the filtering
capabilities that Mailfilter would have otherwise provided. There are also cloud
based services that provide mail filtering as a service at a much larger scale,
across a multitude of organizations.

From a technical perspective, Mailfilter is very fast and has a very low memory
footprint, but even commodity hardware is now so powerful that any difference in
performance could be hardly noticed compared to a less optimized alternative.
For example, something like Mailfilter could be easily implemented in pure
JavaScript (e.g. using Node.js).

That said, Mailfilter is functional, and there are still reasons to use a
private mail exchange. Privacy is the first that comes to mind, and
unfortunately it's not a priority for most users/organizations.

# Evolution

Mailfilter started as a pure C implementation where the filtering logic was
hard-coded into the engine. Some limited customization could be done through the
configuration file and a (mandatory) relational database.

The next iteration added JavaScript (using [SpiderMonkey](https://spidermonkey.dev/))
and removed the direct connection to the relational database. Instead, if the
application required customization using a database, it was to be implemented
using [libjssql](https://github.com/mindbit/libjssql).

The current iteration replaces the JavaScript engine with [Duktape](http://duktape.org/),
mainly because SpiderMonkey dropped the C API support. Realistically, Duktape is
easier to embed into another project because it was specifically created for
this purpose and because the API is much simpler thanks to its data stack
concept.

No major changes are planned or expected. A very high level roadmap includes
stabilization and bringing back some features that were left behind during the
SpiderMonkey iteration, such as the ClamAV integration and DKIM support. Some
new features such as STARTTLS support and DMARC support are also on the radar.
