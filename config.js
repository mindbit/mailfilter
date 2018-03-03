// Switch logging to syslog
Sys.openlog();

// Load the "sql" module. Registers the global "sql" object, which has
// the getConnection(url) method.
Sys.loadModule("mod_sql.so");

// Load the mysql driver module. This enables using URLs that start
// with "mysql://" with the sql.getConnection() method.
Sys.loadModule("mod_mysql.so");

// Load the SMTP client module. This module allows connecting to other
// SMTP servers as a client.
Sys.loadModule("mod_smtp_client.so");

// Configure address/port pairs for listening to incoming SMTP
// connections.
SmtpServer.listenAddress = [["127.0.0.1", 8025]];

// Enable logging of everything that is received and sent on the SMTP
// connection.
SmtpServer.debugProtocol = true;

/*
// Provide the initial SMTP greeting that the server will send to the
// client, as an SmtpStatus object.
smtpServer.initialGreeting = function () {
	// Create SMTP client connection to real server
	this.client = new SmtpClientConnection("127.0.0.1", "25");

	// Create connection to SQL server
	this.db = DriverManager.getConnection("mailfilter", "mailfilter");

	// Create a new record in smtp_transactions and save remote server address and port
	var pstmt = this.db.createPreparedStatement("INSERT INTO smtp_transactions (remote_addr, remote_port) VALUES(?,?)");
	pstmt.setString(1, smtpServer.clientAddress);
	pstmt.setString(2, smtpServer.clientPort);
	pstmt.executeUpdate();
	var res = pstmt.getGeneratedKeys();
	res.next();
	this.smtpTransactionId = res.getString(1);
	pstmt.close();

	// Connect to real server
	return this.client.connect();
	// FIXME connect() tb sa intoarca un SmtpStatus care contine exact greeting-ul de la client sau sa arunce o eroare daca nu se poate conecta
};

// FIXME smtpServer.getEnvelopeSender() intoarce un obiect SmtpPath care modeleaza struct smtp_path din C
smtpServer.smtpMail = function () {
	var envelopeSender = this.getEnvelopeSender();

	// Save the envelope sender in the database
	var pstmt = this.db.createPreparedStatement("UPDATE smtp_transactions SET envelope_sender=? WHERE smtp_transaction_id=?");
	pstmt.setString(1, this.smtpTransactionId);
	pstmt.setString(2, envelopeSender);
	pstmt.executeUpdate();
	pstmt.close();

	// relay the command to the real server
	return this.client.smtpMail(envelopeSender);
};

// FIXME this.getRecipients() intoarce un array de SmtpPath, care modeleaza struct smtp_path din C
smtpServer.smtpRcpt = function () {
	var recipients = this.getRecipients();
	var recipient = recipients[recipients.length - 1];

	// Save the recipient in the database
	var pstmt = this.db.createPreparedStatement("INSERT INTO smtp_transaction_recipients(smtp_transaction_id, recipient) VALUES (?,?)");
	pstmt.setString(1, this.smtpTransactionId);
	pstmt.setString(2, recipient);
	pstmt.executeUpdate();
	pstmt.close();

	// relay the command to the real server
	return this.client.smtpRcpt(recipient);
};

// smtpServer.smtpData = function () {} FIXME deocamdata nu tb sa facem nimic in plus fata de ce e built-in

smtpServer.messageBody = function () {
	// FIXME createReceivedHeader() intoarce un obiect care modeleaza un struct im_header si e generat de create_received_hdr()
	var receivedHeader = this.createReceivedHeader();
	this.insertHeaderBefore(receivedHeader, "received");
	this.client.smtpData();
	// FIXME client.smtpData() ar tb sa intoarca un SmtpStatus pe care sa il si verificam ca e ok
	return this.client.sendMessage(this.getHeaders(), this.getMessageCache());
	// FIXME getHeaders() intoarce un array de obiecte care modeleaza headere
	// getMessageCache() intoarce calea catre fisierul temporar in care e corpul mesajului
	// client.sendMessage() intoarce SmtpStatus
};
*/

SmtpServer.FILTER_ACCEPT = 0;
SmtpServer.FILTER_REJECT_TEMPORARILY = 1;
SmtpServer.FILTER_REJECT_PERMANENTLY = 2;

// List of DNSBL domains:
//   - first element is the DNSBL domain name
//   - second element (optional) is a callback function // TODO
//   - remaining elements (optional) are passed to the callback function // TODO
SmtpServer.dnsbl = [
	["zen.spamhaus.org"],		// Free for "private mail systems with low traffic";
					// https://www.spamhaus.org/organization/dnsblusage/
	["dnsrbl.org"],			// Open; http://dnsrbl.org/
	["rbl.abuse.ro"],		// Open; http://abuse.ro/#three
	//["b.barracudacentral.org"],	// Open; requires registation;
					// http://barracudacentral.org/rbl
];

SmtpServer.bypassFilters = [
	'<test@localhost>',
];

Array.prototype.indexOfStr = function(str)
{
	for (var i in this)
		if (this[i].toString() == str)
			return i;
	return -1;
}

SmtpServer.prototype.relayCmd = function(cmd, args)
{
	this.smtpClient.sendCommand(cmd, args);
	return this.smtpClient.readResponse();
}

SmtpServer.prototype.smtpInit = function()
{
	this.smtpClient = new SmtpClient("127.0.0.1", 25);
	this.smtpClient.connect();
	return this.smtpClient.readResponse();
}

SmtpServer.prototype.smtpHelo = function(hostname)
{
	return this.relayCmd("HELO", hostname);
}

SmtpServer.prototype.smtpEhlo = function(hostname)
{
	return this.relayCmd("EHLO", hostname);
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
	// SMTP server. We should not return an SmtpStatus, since it's
	// ignored anyway by the engine.
	if (!headers || !body) {
		this.relayCmd("RSET");
		return null;
	}

	// Generate and insert the "Received" header
	headers.unshift(this.receivedHeader());

	var bypassFilters = false;
	for (var i in SmtpServer.bypassFilters)
		if (this.recipients.indexOfStr(SmtpServer.bypassFilters[i]) >= 0) {
			bypassFilters = true;
			break;
		}

	switch (this.filter(headers, body)) {
	case SmtpServer.FILTER_REJECT_TEMPORARILY:
		Sys.log(Sys.LOG_INFO, "FILTER: REJECT-TEMPORARILY");
		if (bypassFilters)
			break;
		this.relayCmd("RSET");
		return new SmtpResponse(450, "Requested action not taken");
	case SmtpServer.FILTER_REJECT_PERMANENTLY:
		Sys.log(Sys.LOG_INFO, "FILTER: REJECT-PERMANENTLY");
		if (bypassFilters)
			break;
		this.relayCmd("RSET");
		return new SmtpResponse(550, "Requested action not taken");
	default:
		Sys.log(Sys.LOG_INFO, "FILTER: ACCEPT");
		bypassFilters = false;
	}

	if (bypassFilters) {
		Sys.log(Sys.LOG_INFO, "bypassed filter action");
		for (var i in headers) {
			if (headers[i].name.toLowerCase() != "subject")
				continue;
			var parts = headers[i].parts;
			parts[0] = "[SPAM] " + parts[0];
			break;
		}
	}

	var rsp = this.relayCmd("DATA");
	if (rsp.code != 354)
		return rsp;

	this.smtpClient.sendMessage(headers, body);
	return this.smtpClient.readResponse();
}

SmtpServer.prototype.smtpRset = function() {
	return this.relayCmd("RSET");
};

SmtpServer.prototype.cleanup = function() {
	this.relayCmd("QUIT");
	this.smtpClient.disconnect();
};

SmtpServer.prototype.filter = function(headers, body) {
	if (!this.sender.mailbox.domain) {
		Sys.log(Sys.LOG_DEBUG, "Sender: null");
		return SmtpServer.FILTER_REJECT_PERMANENTLY;
	}

	var srv = new SpfServer(Spf.DNS_CACHE);
	var rsp = srv.query(this.remoteAddr, this.sender.mailbox.domain);
	Sys.dump(rsp);
	switch (rsp.result) {
	case Spf.RESULT_NEUTRAL:
		Sys.log(Sys.LOG_DEBUG, "SPF: ? (Neutral)");
		break;
	case Spf.RESULT_PASS:
		Sys.log(Sys.LOG_DEBUG, "SPF: + (Pass)");
		break;
	case Spf.RESULT_FAIL:
		Sys.log(Sys.LOG_DEBUG, "SPF: - (Fail)");
		return SmtpServer.FILTER_REJECT_PERMANENTLY;
	case Spf.RESULT_SOFTFAIL:
		Sys.log(Sys.LOG_DEBUG, "SPF: ~ (Softfail)");
		// TODO increase spam score
		break;
	case Spf.RESULT_NONE:
		Sys.log(Sys.LOG_DEBUG, "SPF: X (None)");
		break;
	case Spf.RESULT_TEMPERROR:
		Sys.log(Sys.LOG_DEBUG, "SPF: T (TempError)");
		return SmtpServer.FILTER_REJECT_TEMPORARILY;
	case Spf.RESULT_PERMERROR:
		Sys.log(Sys.LOG_DEBUG, "SPF: P (PermError)");
		// We get PermError if e.g. the domain declares multiple SPF records. In that case
		// it means the SPF check is unreliable, so we just go on with other checks.
		// TODO increase spam score
		break;
	}

	for (var i in SmtpServer.dnsbl) {
		var dnsbl = SmtpServer.dnsbl[i];
		var raddr = Dns.revAddr(this.remoteAddr, dnsbl[0]);
		var result = Dns.query(raddr, Dns.t_a);
		if (typeof(result) == "number") {
			Sys.log(Sys.LOG_DEBUG, "DNSBL: pass " + raddr + " (" + result + ")");
			continue;
		}
		var rlist = [];
		for (var j in result.answer) {
			var rr = result.answer[j];
			if (rr.type = Dns.t_a && rr.name.toLowerCase() == raddr.toLowerCase())
				rlist.push(rr.data);
		}
		// TODO if `dnsbl` defines a callback function, call it and pass rlist
		Sys.log(Sys.LOG_DEBUG, "DNSBL: reject " + raddr + " (" + rlist.join() + ")");
		return SmtpServer.FILTER_REJECT_PERMANENTLY;
	}

	return SmtpServer.FILTER_ACCEPT;
}

/*
smtpServer.smtpAuth = function() {
	return {
		"code" : 250,
		"message" : "auth from JS",
		"disconnect" : false
	};
}

smtpServer.smtpAlou = function() {
	return {
		"code" : 250,
		"message" : "alou from JS",
		"disconnect" : false
	};
}

smtpServer.smtpAlop = function() {
	return {
		"code" : 250,
		"message" : "alop from JS",
		"disconnect" : false
	};
}
*/
