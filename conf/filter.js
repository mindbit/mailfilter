/*
 * Reverse proxy configuration where suspicious emails are rejected
 * immediately, without being forwarded to the backend SMTP server.
 */

// Uncomment the line below to switch logging to syslog
//Sys.openlog();

// Configure address/port pairs for listening to incoming SMTP
// connections.
SmtpServer.listenAddress = [["127.0.0.1", 8025]];

// Enable logging of everything that is received and sent on the SMTP
// connection.
SmtpServer.debugProtocol = true;

SmtpServer.FILTER_ACCEPT = 0;
SmtpServer.FILTER_ACCEPT_MARK = 1;
SmtpServer.FILTER_REJECT_TEMPORARILY = 2;
SmtpServer.FILTER_REJECT_PERMANENTLY = 3;
SmtpServer.FILTER_REJECT_VIRUS = 4;

// List of DNSBL domains:
//   - first element is the DNSBL domain name
//   - second element (optional) is a callback function // TODO
//   - remaining elements (optional) are passed to the callback function // TODO
// See https://www.dnsbl.info/dnsbl-list.php for a list of (active) DNS blacklists
SmtpServer.dnsbl = [
	//["zen.spamhaus.org"],		// Free for "private mail systems with low traffic";
					// https://www.spamhaus.org/organization/dnsblusage/
	["bl.spamcop.net"],		// Open; https://www.spamcop.net/bl.shtml
	//["rbl.abuse.ro"],		// Open; https://abuse.ro/#three
	//["b.barracudacentral.org"],	// Open; https://barracudacentral.org/
];

// If an email to any of the recipients below is identified as SPAM, accept it
// and prepend the "[SPAM] " string to the Subject header, instead of rejecting
// the email.
SmtpServer.bypassFilters = [
	'<test@localhost>',
];

// If the sender domain is one of the domains below AND the SPF check has passed,
// accept the email and prepend the "[SPAM] " string to the Subject header in
// case further checks (such as DNS RBL) fail.
SmtpServer.trustSpfDomains = [
	'gmail.com',
	'yahoo.com',
];

Object.defineProperty(Array.prototype, "indexOfStr", {
	value: function(str) {
		for (var i in this)
			if (this[i].toString() == str)
				return i;
		return -1;
	},
	enumerable: false
});

function addSubjectTag(headers, tag)
{
	for (var i in headers) {
		if (headers[i].name.toLowerCase() != "subject")
			continue;
		var parts = headers[i].parts;
		parts[0] = "[" + tag + "] " + parts[0];
		return;
	}
	headers.push(new SmtpHeader("Subject", "[" + tag + "]"));
}

SmtpServer.prototype.relayCmd = function(cmd, args)
{
	this.smtpClient.sendCommand(cmd, args);
	return this.smtpClient.readResponse();
}

// Provide the initial SMTP greeting that the server will send to the
// client, as a SmtpResponse object.
SmtpServer.prototype.smtpInit = function()
{
	// Create a SMTP client object pointing to the real server
	//    .     WARNING  Do not set the address below to 127.0.0.1 unless
	//   / \    WARNING  you really know what you're doing. Because this
	//  / ! \   WARNING  address is trusted in most default configurations,
	// '-----'  WARNING  it will likely turn your system into an open relay.
	this.smtpClient = new SmtpClient("192.168.0.1");
	// Connect to the real server
	this.smtpClient.connect();
	// Read the greeting and pass it back to our client
	return this.smtpClient.readResponse();
}

SmtpServer.prototype.smtpHelo = function(hostname)
{
	return this.relayCmd("HELO", this.hostname);
}

SmtpServer.prototype.smtpEhlo = function(hostname)
{
	return this.relayCmd("EHLO", this.hostname);
}

SmtpServer.prototype.smtpMail = function(path)
{
	return this.relayCmd("MAIL", "FROM: " + path.toString());
}

SmtpServer.prototype.smtpRcpt = function(path)
{
	return this.relayCmd("RCPT", "TO: " + path.toString());
}

SmtpServer.prototype.smtpData = function(headers, body)
{
	// Normally both "headers" and "body" should be non-null. If at
	// least one of them is null, it means the SMTP engine rejected
	// the DATA command (e.g. the message failed to parse). In this
	// case we need to clean up the transaction state with the real
	// SMTP server. We should not return a SmtpResponse, since it's
	// ignored anyway by the engine.
	if (!headers || !body) {
		this.relayCmd("RSET");
		return null;
	}

	// Generate and insert the "Received" header
	headers.unshift(this.receivedHeader());

	var bypassFilters = false;
	var tag = "SPAM";
	for (var i in SmtpServer.bypassFilters)
		if (this.recipients.indexOfStr(SmtpServer.bypassFilters[i]) >= 0) {
			bypassFilters = true;
			break;
		}

	switch (this.filter(headers, body)) {
	case SmtpServer.FILTER_REJECT_TEMPORARILY:
		Sys.log(Sys.LOG_INFO, "Filter: REJECT-TEMPORARILY");
		if (bypassFilters)
			break;
		this.relayCmd("RSET");
		return new SmtpResponse(450, "Requested action not taken");
	case SmtpServer.FILTER_REJECT_VIRUS:
		tag = "VIRUS";
		// fallthrough
	case SmtpServer.FILTER_REJECT_PERMANENTLY:
		Sys.log(Sys.LOG_INFO, "Filter: REJECT-PERMANENTLY");
		if (bypassFilters)
			break;
		this.relayCmd("RSET");
		return new SmtpResponse(550, "Requested action not taken");
	case SmtpServer.FILTER_ACCEPT_MARK:
		Sys.log(Sys.LOG_INFO, "Filter: ACCEPT-MARK");
		bypassFilters = true;
		break;
	default:
		Sys.log(Sys.LOG_INFO, "Filter: ACCEPT");
		bypassFilters = false;
	}

	if (bypassFilters) {
		Sys.log(Sys.LOG_INFO, "Bypassed filter action");
		addSubjectTag(headers, tag)
	}

	var rsp = this.relayCmd("DATA");
	if (rsp.code != 354)
		return rsp;

	this.smtpClient.sendMessage(headers, body);
	return this.smtpClient.readResponse();
}

SmtpServer.prototype.smtpStartTls = function() {
	return this.relayCmd("RSET");
};

SmtpServer.prototype.smtpRset = function() {
	return this.relayCmd("RSET");
};

SmtpServer.prototype.cleanup = function() {
	this.relayCmd("QUIT");
	this.smtpClient.disconnect();
};

SmtpServer.prototype.filter = function(headers, body) {
	var srv = new ClamAV("localhost");
	var rsp = srv.scan(headers, body);
	Sys.log(Sys.LOG_INFO, "ClamAV: " + JSON.stringify(rsp));
	if (rsp && rsp.found)
		return SmtpServer.FILTER_REJECT_VIRUS;

	if (!this.sender.mailbox.domain) {
		Sys.log(Sys.LOG_DEBUG, "Sender: null");
		return SmtpServer.FILTER_REJECT_PERMANENTLY;
	}

	var srv = new SpfServer(Spf.DNS_CACHE);
	var rsp = srv.query(this.remoteAddr, this.sender.mailbox.domain);
	Sys.log(Sys.LOG_INFO, "SPF: " + Spf.resultStrMap[rsp.result]);
	if (rsp.result == Spf.RESULT_TEMPERROR)
		return SmtpServer.FILTER_REJECT_TEMPORARILY;
	if (rsp.result == Spf.RESULT_FAIL)
		return SmtpServer.FILTER_REJECT_PERMANENTLY;
	// We get PermError if e.g. the domain declares multiple SPF records. In that case
	// it means the SPF check is unreliable, so we just go on with other checks.
	// TODO increase spam score for SoftFail and PermError

	var ret = SmtpServer.FILTER_REJECT_PERMANENTLY;
	if (rsp.result == Spf.RESULT_PASS && SmtpServer.trustSpfDomains.indexOfStr(this.sender.mailbox.domain) >= 0)
		ret = SmtpServer.FILTER_ACCEPT_MARK;

	for (var i in SmtpServer.dnsbl) {
		var dnsbl = SmtpServer.dnsbl[i];
		var raddr = Dns.revAddr(this.remoteAddr, dnsbl[0]);
		var result = Dns.query(raddr, Dns.t_a);
		if (typeof(result) == "number") {
			Sys.log(Sys.LOG_INFO, "DNSBL: pass " + raddr + " (" + result + ")");
			continue;
		}
		var rlist = [];
		for (var j in result.answer) {
			var rr = result.answer[j];
			if (rr.type = Dns.t_a && rr.name.toLowerCase() == raddr.toLowerCase())
				rlist.push(rr.data);
		}
		// TODO if `dnsbl` defines a callback function, call it and pass rlist
		Sys.log(Sys.LOG_INFO, "DNSBL: reject " + raddr + " (" + rlist.join() + ")");
		return ret;
	}

	var srv = new SpamAssassin("localhost");
	var rsp = srv.scan(headers, body);
	Sys.log(Sys.LOG_INFO, "SpamAssassin: " + JSON.stringify(rsp));
	if (rsp && rsp.spam)
		return ret;

	return SmtpServer.FILTER_ACCEPT;
}
