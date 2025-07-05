/*
 * Reverse proxy configuration that forwards all emails to the
 * backend SMTP server. This configuration just demonstrates the SMTP
 * proxy capabilities of Mailfilter and serves no practical purpose.
 * It is one of the most basic Mailfilter configurations.
 */

// Uncomment the line below to switch logging to syslog
//Sys.openlog("mailfilter", Sys.LOG_MAIL);

// Configure address/port pairs for listening to incoming SMTP
// connections.
SmtpServer.listenAddress = [["127.0.0.1", 8025]];

// Enable logging of everything that is received and sent on the SMTP
// connection.
SmtpServer.debugProtocol = true;

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
