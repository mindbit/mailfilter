engine.logging = {
	type: "stderr",
	level: "debug",
	facility: "mail"
};

// Enable logging of everything that is received and sent on the SMTP
// connection.
engine.debugProtocol = true;

// Load the "sql" module. Registers the global "sql" object, which has
// the getConnection(url) method.
engine.loadModule("mod_sql.so");

// Load the mysql driver module. This enables using URLs that start
// with "mysql://" with the sql.getConnection() method.
engine.loadModule("mod_mysql.so");

// Load the SMTP client module. This module allows connecting to other
// SMTP servers as a client.
engine.loadModule("mod_smtp_client.so");


smtpServer.listenAddress = [["127.0.0.1", "8025"]];

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
/*
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

function relayCmd(cmd) {
	smtpClient.sendCommand(cmd);
	return smtpClient.readResponse();
}

smtpServer.smtpInit = function() {
	smtpClient = new SmtpClient("127.0.0.1", "25");
	smtpClient.connect();
	return smtpClient.readResponse();
}

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

smtpServer.smtpEhlo = function() {
	return relayCmd("EHLO");
}

smtpServer.smtpHelo = function() {
	return relayCmd("HELO");
}

smtpServer.smtpData = function() {
	smtpClient.sendCommand("DATA");
	var dataResponse = smtpClient.readResponse();

	if (dataResponse.code != 354) {
		// throw exceptie
	}

	smtpClient.sendMessageBody(smtpServer.session.headers, smtpServer.session.pathToBody);
	return smtpClient.readResponse();
}

smtpServer.smtpMail = function() {
	smtpClient.sendCommand("MAIL", "FROM: " + smtpServer.session.envelopeSender.toString());
	return smtpClient.readResponse();
}

smtpServer.smtpRcpt = function() {
	var lastID = smtpServer.session.recipients.length - 1;
	var lastRecipient = smtpServer.session.recipients[lastID];
	smtpClient.sendCommand("RCPT", "TO: " + lastRecipient.toString());
	return smtpClient.readResponse();
}

smtpServer.smtpRset = function () {
	return relayCmd("RSET");
};

smtpServer.smtpQuit = function () {
	return relayCmd("QUIT");
};

smtpServer.smtpClnp = function () {
	relayCmd("CLNP");
};

