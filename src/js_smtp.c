#include "js_smtp.h"
#include "smtp.h"
#include "bfd.h"
#include "js_main.h"
#include "string_tools.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <sys/socket.h>
#include <sys/types.h>

extern JSContext *js_context; // FIXME pass through arguments

jsval create_response(JSContext *cx, int code, const char* message, int disconnect) { 
	jsval response, js_code, js_message, js_disconnect;

	if (message != NULL) {
		js_message = STRING_TO_JSVAL(JS_InternString(cx, message));
	} else {
		js_message = STRING_TO_JSVAL(JS_InternString(cx, "default err message"));
	}

	js_code = INT_TO_JSVAL(code);
	js_disconnect = JSVAL_FALSE;

	jsval argv[] = {js_code, js_message, js_disconnect};

	response = js_create_response(argv);
	return response;
}

/* {{{ SmtpPath */

static JSClass SmtpPath_class = {
	"SmtpPath", 0, JS_PropertyStub, JS_PropertyStub,
	JS_PropertyStub, JS_StrictPropertyStub, JS_EnumerateStub,
	JS_ResolveStub, JS_ConvertStub, NULL,
	JSCLASS_NO_OPTIONAL_MEMBERS
};

static JSBool SmtpPath_construct(JSContext *cx, unsigned argc, jsval *vp)
{
	jsval path, smtpPath;
	JSObject *domains, *mailbox, *obj;

	path = JS_ARGV(cx, vp)[0];

	char *c_str = JS_EncodeString(cx, JSVAL_TO_STRING(path));
	char *trailing = c_str;

	obj = JS_NewObjectForConstructor(cx, &SmtpPath_class, vp);
	if (!obj)
		return JS_FALSE;

	// Add domains property
	domains = JS_NewArrayObject(cx, 0, NULL);

	if (!domains)
		return JS_FALSE;

	if (!JS_DefineProperty(cx, obj, "domains", OBJECT_TO_JSVAL(domains), NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT))
		return JS_FALSE;

	// Add mailbox property
	mailbox = JS_NewObject(cx, NULL, NULL, NULL);

	if (!mailbox)
		return JS_FALSE;

	if (!JS_DefineProperty(cx, mailbox, "local", STRING_TO_JSVAL(JS_InternString(cx, "")), NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT))
		return JS_FALSE;

	if (!JS_DefineProperty(cx, mailbox, "domain", STRING_TO_JSVAL(JS_InternString(cx, "")), NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT))
		return JS_FALSE;

	if (!JS_DefineProperty(cx, obj, "mailbox", OBJECT_TO_JSVAL(mailbox), NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT))
		return JS_FALSE;

	smtpPath = OBJECT_TO_JSVAL(obj);

	smtp_path_parse(&smtpPath, c_str, &trailing);

	JS_free(cx, c_str);

	JS_SET_RVAL(cx, vp, smtpPath);
	return JS_TRUE;
}

static JSBool SmtpPath_toString(JSContext *cx, unsigned argc, jsval *vp)
{
	jsval domain, local, domains, smtpPath, mailbox, rval;
	int str_len, i;
	uint32_t domains_len;

	smtpPath = JS_THIS(cx, vp);

	// Get domains
	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(smtpPath), "domains", &domains)) {
		return JS_FALSE;
	}

	// Get mailbox
	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(smtpPath), "mailbox", &mailbox)) {
		return JS_FALSE;
	}

	// Get mailbox.local
	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(mailbox), "local", &local)) {
		return JS_FALSE;
	}
	// Get mailbox.domain
	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(mailbox), "domain", &domain)) {
		return JS_FALSE;
	}

	// +1 for "@"
	str_len = JS_GetStringLength(JSVAL_TO_STRING(local))
			+ JS_GetStringLength(JSVAL_TO_STRING(domain))
			+ 1;

	// Get number of domains
	if (!JS_GetArrayLength(cx, JSVAL_TO_OBJECT(domains), &domains_len)) {
		return -1;
	}

	for (i = 0; i < (int) domains_len; i++) {
		if (!JS_GetElement(cx, JSVAL_TO_OBJECT(domains), i, &rval)) {
			return -1;
		}

		str_len += JS_GetStringLength(JSVAL_TO_STRING(rval));
	}

	// Add space for "@" * domains_len and "," * (domains_len - 1)
	str_len += 2 * domains_len - 1;

	// Add space for "<", ">" and ":"
	str_len += 3;

	char *c_str = malloc(str_len + 1);

	strcpy(c_str, "<");

	for (i = 0; i < domains_len; i++) {
		if (!JS_GetElement(cx, JSVAL_TO_OBJECT(domains), i, &rval)) {
			return -1;
		}

		strcat(c_str, "@");
		strcat(c_str, JS_EncodeString(cx, JSVAL_TO_STRING(rval)));

		if (domains_len != 1 && i < domains_len - 1) {
			strcat(c_str, ",");
		}
	}

	if (domains_len > 0) {
		strcat(c_str, ":");
	}

	strcat(c_str, JS_EncodeString(cx, JSVAL_TO_STRING(local)));

	strcat(c_str, "@");

	strcat(c_str, JS_EncodeString(cx, JSVAL_TO_STRING(domain)));

	strcat(c_str, ">");

	strcat(c_str, "\0");

	JS_SET_RVAL(cx, vp, STRING_TO_JSVAL(JS_InternString(cx, c_str)));

	free(c_str);

	return JS_TRUE;
}

static JSFunctionSpec SmtpPath_functions[] = {
	JS_FS("toString", SmtpPath_toString, 0, 0),
	JS_FS_END
};

/* }}} SmtpPath */

/* {{{ SmtpHeader */

static JSClass SmtpHeader_class = {
	"SmtpHeader", 0, JS_PropertyStub, JS_PropertyStub,
	JS_PropertyStub, JS_StrictPropertyStub, JS_EnumerateStub,
	JS_ResolveStub, JS_ConvertStub, NULL,
	JSCLASS_NO_OPTIONAL_MEMBERS
};

static JSBool SmtpHeader_construct(JSContext *cx, unsigned argc, jsval *vp)
{
	jsval name, parts_recv;
	JSObject *obj;
	JSObject *parts_obj;
	jsval parts;

	name = JS_ARGV(cx, vp)[0];
	parts_recv = JS_ARGV(cx, vp)[1];

	obj = JS_NewObjectForConstructor(cx, &SmtpHeader_class, vp);
	if (!obj)
		return JS_FALSE;

	// Set name property
	if (JS_SetProperty(js_context, obj, "name", &name))
		return JS_FALSE;

	// Add parts property
	switch(JS_TypeOfValue(js_context, parts_recv)) {
	case JSTYPE_STRING:
		// Create the messages array property
		parts_obj = JS_NewArrayObject(js_context, 0, NULL);

		if (!parts_obj)
			return JS_FALSE;

		// Add message to messages array
		if (!JS_SetElement(js_context, parts_obj, 0, &parts_recv))
			return JS_FALSE;

		// Copy the messages to the property
		parts = OBJECT_TO_JSVAL(parts_obj);

		if (!JS_SetProperty(js_context, obj, "parts", &parts))
			return JS_FALSE;

		break;
	case JSTYPE_OBJECT:
		// Copy the messages to the property
		if (!JS_SetProperty(js_context, obj, "parts", &parts_recv))
			return JS_FALSE;

		break;
	default:
		return JS_FALSE;
	}

	JS_SET_RVAL(cx, vp, OBJECT_TO_JSVAL(obj));
	return JS_TRUE;
}

static JSBool SmtpHeader_getValue(JSContext *cx, unsigned argc, jsval *vp)
{
	jsval parts, rval;
	jsval header;

	uint32_t parts_len, header_len;
	int i;
	char *c_str, *header_no_wsp;

	// Get header
	header = JS_THIS(cx, vp);

	// Get parts
	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(header), "parts", &parts)) {
		return JS_FALSE;
	}

	// Get number of parts
	if (!JS_GetArrayLength(cx, JSVAL_TO_OBJECT(parts), &parts_len)) {
		return -1;
	}

	if (parts_len == 0) {
		JS_SET_RVAL(cx, vp, STRING_TO_JSVAL(JS_InternString(cx, "")));

		return JS_TRUE;
	}

	header_len = 0;

	for (i = 0; i < (int) parts_len; i++) {
		if (!JS_GetElement(cx, JSVAL_TO_OBJECT(parts), i, &rval)) {
			return -1;
		}
		header_len += JS_GetStringLength(JSVAL_TO_STRING(rval));
	}

	header_len += 3 * ((int) parts_len - 1);

	c_str = malloc(header_len + 1);

	if (!JS_GetElement(cx, JSVAL_TO_OBJECT(parts), 0, &rval)) {
		return -1;
	}

	// Remove beginning whitespace chars
	header_no_wsp = JS_EncodeString(cx, JSVAL_TO_STRING(rval));
	string_remove_beginning_whitespace(header_no_wsp);

	strcpy(c_str, header_no_wsp);
	strcat(c_str, " ");

	free(header_no_wsp);

	for (i = 1; i < (int) parts_len; i++) {
		if (!JS_GetElement(cx, JSVAL_TO_OBJECT(parts), i, &rval)) {
			return -1;
		}

		// Remove beginning whitespace chars
		header_no_wsp = JS_EncodeString(cx, JSVAL_TO_STRING(rval));
		string_remove_beginning_whitespace(header_no_wsp);

		strcat(c_str, header_no_wsp);
		free(header_no_wsp);

		if (i < (int) (parts_len - 1)) {
			strcat(c_str, " ");
		}
	}

	strcat(c_str, "\0");

	JS_SET_RVAL(cx, vp, STRING_TO_JSVAL(JS_InternString(cx, c_str)));

	free(c_str);

	return JS_TRUE;
}

static JSBool SmtpHeader_toString(JSContext *cx, unsigned argc, jsval *vp)
{
	jsval rval, hname, parts, part;
	uint32_t parts_len;
	int i;

	jsval header = JS_THIS(cx, vp);
	// Get name
	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(header), "hname", &hname)) {
		return JS_FALSE;
	}

	// Get parts
	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(header), "parts", &parts)) {
		return JS_FALSE;
	}

	// Get number of parts
	if (!JS_GetArrayLength(cx, JSVAL_TO_OBJECT(parts), &parts_len)) {
		return -1;
	}

	rval = STRING_TO_JSVAL(JS_ConcatStrings(cx, JSVAL_TO_STRING(hname), JS_InternString(cx, ": ")));

	for (i = 0; i < (int) parts_len; i++) {
		if (!JS_GetElement(cx, JSVAL_TO_OBJECT(parts), i, &part)) {
			return -1;
		}

		rval = STRING_TO_JSVAL(JS_ConcatStrings(cx, JSVAL_TO_STRING(rval), JSVAL_TO_STRING(part)));

		if (i < (int) parts_len - 1) {
			rval = STRING_TO_JSVAL(JS_ConcatStrings(cx, JSVAL_TO_STRING(rval), JS_InternString(cx, "\r\n")));
		}
	}

	JS_SET_RVAL(cx, vp, rval);
	return JS_TRUE;
}

static JSBool SmtpHeader_refold(JSContext *cx, unsigned argc, jsval *vp)
{
	jsval hname, value, parts, header;
	int width, len;
	char /* *c_name, */ *c_value, *p1, *p2, *p3, *c_part;

	width = JSVAL_TO_INT(JS_ARGV(cx, vp)[0]);
	header = JS_THIS(cx, vp);

	// Get name
	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(header), "hname", &hname)) {
		return JS_FALSE;
	}

	// Get value
	if (SmtpHeader_getValue(cx, argc, vp)) {
		value = *vp;
	}

	// Delete header parts
	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(header), "parts", &parts))
		return JS_FALSE;
	if (!JS_SetArrayLength(cx, JSVAL_TO_OBJECT(parts), 0))
		return JS_FALSE;

	//c_name = JS_EncodeString(cx, JSVAL_TO_STRING(hname));
	c_value = JS_EncodeString(cx, JSVAL_TO_STRING(value));

	p1 = c_value;
	p2 = p1;
	p3 = c_value;
	len = 0;

	do {
		int count = 0;
		do {
			len += p2 - p1;
			p1 = p2;

			if ((p2 = strchr(p1, ' ')) == NULL) {
				c_part = malloc(strlen(c_value) + 2);
				c_part[0] = '\t';
				strncpy(c_part + 1, c_value, strlen(c_value) + 1);
				add_part_to_header(&header, c_part);
				free(c_part);
				free(p3);
				return JS_TRUE;
			}
			p2++;
			count++;
		} while (len + p2 - p1 < width);

		// Add tab, then header, then null terminator
		c_part = malloc(len + 1);
		c_part[0] = '\t';
		strncpy(c_part + 1, c_value, len - 1);
		c_part[len] = '\0';

		// Add this new part to header.parts
		add_part_to_header(&header, c_part);
		c_value += len;
		free(c_part);

		len = 0;
	} while (1);

	return JS_TRUE;
}

static JSFunctionSpec SmtpHeader_functions[] = {
	JS_FS("getValue", SmtpHeader_getValue, 0, 0),
	JS_FS("toString", SmtpHeader_toString, 0, 0),
	JS_FS("refold", SmtpHeader_refold, 0, 0),
	JS_FS_END
};

/* }}} SmtpHeader */

/* {{{ SmtpResponse */

static JSClass SmtpResponse_class = {
	"SmtpResponse", 0, JS_PropertyStub, JS_PropertyStub,
	JS_PropertyStub, JS_StrictPropertyStub, JS_EnumerateStub,
	JS_ResolveStub, JS_ConvertStub, NULL,
	JSCLASS_NO_OPTIONAL_MEMBERS
};

static JSBool SmtpResponse_construct(JSContext *cx, unsigned argc, jsval *vp)
{
	jsval code, messages, disconnect;
	jsval aux;
	JSObject *obj, *messages_arr;

	code = JS_ARGV(cx, vp)[0];
	messages = JS_ARGV(cx, vp)[1];
	disconnect = JS_ARGV(cx, vp)[2];

	obj = JS_NewObjectForConstructor(cx, &SmtpResponse_class, vp);
	if (!obj)
		return JS_FALSE;

	// Add code property
	if (!JS_SetProperty(cx, obj, "code", &code))
		return JS_FALSE;

	// Add messages property
	switch(JS_TypeOfValue(cx, messages)) {
	case JSTYPE_STRING:
		// Create the messages array property
		messages_arr = JS_NewArrayObject(cx, 0, NULL);

		if (!messages_arr)
			return JS_FALSE;

		// Add message to messages array
		if (!JS_SetElement(cx, messages_arr, 0, &messages))
			return JS_FALSE;

		// Copy the messages to the property
		aux = OBJECT_TO_JSVAL(messages_arr);
		if (!JS_SetProperty(cx, obj, "messages", &aux))
			return JS_FALSE;

		break;
	case JSTYPE_OBJECT:
		// Copy the messages to the property
		if (!JS_SetProperty(cx, obj, "messages", &messages))
			return JS_FALSE;

		break;
	default:
		return JS_FALSE;
	}

	// Add disconnect property
	if (!JS_SetProperty(cx, obj, "disconnect", &disconnect))
		return JS_FALSE;

	JS_SET_RVAL(cx, vp, OBJECT_TO_JSVAL(obj));
	return JS_TRUE;
}

/* }}} SmtpResponse */

static int connect_to_address(char *ip, char *port)
{
	int sockfd, portno;
	struct sockaddr_in serv_addr;
	struct hostent *server;

	portno = atoi(port);
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd < 0) {
		// throw exc
		printf("sock failed\n");
		return -1;
	}

	server = gethostbyname(ip);

	if (!server) {
		// throw exc
		printf("server failed\n");
	}

	bzero((char*) &serv_addr, sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;

	bcopy((char *) server->h_addr, (char *) &serv_addr.sin_addr.s_addr, server->h_length);
	serv_addr.sin_port = htons(portno);

	if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		JS_ReportError(js_context, "Cannot connect to %s:%s!", ip, port);
		return -1;
	}

	return sockfd;
}

/* {{{ SmtpClient */

static JSClass SmtpClient_class = {
	"SmtpClient", 0, JS_PropertyStub, JS_PropertyStub,
	JS_PropertyStub, JS_StrictPropertyStub, JS_EnumerateStub,
	JS_ResolveStub, JS_ConvertStub, NULL,
	JSCLASS_NO_OPTIONAL_MEMBERS
};

static JSBool SmtpClient_construct(JSContext *cx, unsigned argc, jsval *vp)
{
	JSObject *obj;
	jsval host, port;

	host = JS_ARGV(cx, vp)[0];
	port = JS_ARGV(cx, vp)[1];

	obj = JS_NewObjectForConstructor(cx, &SmtpClient_class, vp);
	if (!obj)
		return JS_FALSE;

	// Add host
	if (!JS_SetProperty(cx, obj, "host", &host))
		return JS_FALSE;

	// Add port
	if (!JS_SetProperty(cx, obj, "port", &port))
		return JS_FALSE;

	JS_SET_RVAL(cx, vp, OBJECT_TO_JSVAL(obj));
	return JS_TRUE;
}

static JSBool SmtpClient_connect(JSContext *cx, unsigned argc, jsval *vp) {
	jsval host, port, client, clientStream;
	char *c_host, *c_port;
	int sockfd;
	bfd_t *client_stream;

	client = JS_THIS(cx, vp);

	// Get host
	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(client), "host", &host)) {
		return JS_FALSE;
	}

	// Get port
	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(client), "port", &port)) {
		return JS_FALSE;
	}

	c_host = JS_EncodeString(cx, JSVAL_TO_STRING(host));
	c_port = JS_EncodeString(cx, JSVAL_TO_STRING(port));

	sockfd = connect_to_address(c_host, c_port);

	client_stream = bfd_alloc(sockfd);
	clientStream = PRIVATE_TO_JSVAL(client_stream);

	if (!JS_SetProperty(cx, JSVAL_TO_OBJECT(client), "clientStream", &clientStream)) {
		return JS_FALSE;
	}

	free(c_host);
	free(c_port);

	return JS_TRUE;
}

static JSBool SmtpClient_readResponse(JSContext *cx, unsigned argc, jsval *vp) {
	jsval smtpClient, content, response, clientStream;
	jsval js_code, js_messages, js_disconnect;
	JSObject *messages_obj, *global;

	int code, lines_count;
	char buf[SMTP_COMMAND_MAX + 1], *p, sep;
	ssize_t sz;
	bfd_t *client_stream;

	global = JS_GetGlobalForScopeChain(cx);
	smtpClient = JS_THIS(cx, vp);
	messages_obj = JS_NewArrayObject(cx, 0, 0);

	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(smtpClient), "clientStream", &clientStream)) {
		return JS_FALSE;
	}

	client_stream = JSVAL_TO_PRIVATE(clientStream);

	lines_count = 0;
	do {
		sz = 0;
		do {
			buf[SMTP_COMMAND_MAX] = '\n';
			if ((sz = bfd_read_line(client_stream, buf, SMTP_COMMAND_MAX)) <= 0)
				return JS_FALSE;
		} while (buf[SMTP_COMMAND_MAX] != '\n');
		buf[sz] = '\0';

		if (sz < 4)
			return JS_FALSE;

		sep = buf[3];
		buf[3] = '\0';
		code = strtol(buf, &p, 10);

		if ((sep != ' ' && sep != '-') || *p != '\0')
			return JS_FALSE;
		if (code < 100 || code > 999)
			return JS_FALSE;

		if (buf[sz - 1] == '\n')
			buf[--sz] = '\0';
		if (buf[sz - 1] == '\r')
			buf[--sz] = '\0';

		//add response
		content = STRING_TO_JSVAL(JS_InternString(cx, buf + 4));
		if (!JS_SetElement(cx, messages_obj, lines_count++, &content)) {
			return -1;
		}
	} while (sep == '-');

	js_code = INT_TO_JSVAL(code);
	js_messages = OBJECT_TO_JSVAL(messages_obj);
	js_disconnect = JSVAL_FALSE;
	jsval argv[] = {js_code, js_messages, js_disconnect};

	JS_CallFunctionName(cx, global, "SmtpResponse",
				3, argv, &response);

	JS_SET_RVAL(cx, vp, response);
	return JS_TRUE;
}

static JSBool SmtpClient_sendCommand(JSContext *cx, unsigned argc, jsval *vp) {
	jsval command, args, smtpClient, clientStream;
	char *c_str;
	bfd_t *client_stream;
	// FIXME don't use "sb"; write directly to stream because it's
	// buffered anyway
	struct string_buffer sb = STRING_BUFFER_INITIALIZER;

	command = JS_ARGV(cx, vp)[0];

	if (argc > 1) {
		args = JS_ARGV(cx, vp)[1];
	} else {
		args = JSVAL_NULL;
	}

	smtpClient = JS_THIS(cx, vp);

	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(smtpClient), "clientStream", &clientStream)) {
		return JS_FALSE;
	}

	client_stream = JSVAL_TO_PRIVATE(clientStream);

	// Add command name
	c_str = JS_EncodeString(cx, JSVAL_TO_STRING(command));
	if (string_buffer_append_string(&sb, c_str))
		goto out_err_free;

	free(c_str);

	if (string_buffer_append_char(&sb, ' '))
		goto out_err;

	if (!JSVAL_IS_NULL(args)) {
		c_str = JS_EncodeString(cx, JSVAL_TO_STRING(args));
		if (string_buffer_append_string(&sb, c_str))
			goto out_err_free;
		free(c_str);
	}

	if (string_buffer_append_string(&sb, "\r\n"))
		goto out_err;

	if (bfd_puts(client_stream, sb.s) < 0) {
		goto out_err;
	}

	bfd_flush(client_stream);
	string_buffer_cleanup(&sb);

	return JS_TRUE;

out_err_free:
	free(c_str);
out_err:
	string_buffer_cleanup(&sb);
	bfd_close(client_stream);
	return JS_FALSE;
}

static JSBool SmtpClient_sendMessageBody(JSContext *cx, unsigned argc, jsval *vp) {
	jsval headers, path, smtpClient, rval, clientStream;
	char *c_path, *c_header;
	int i, bodyfd;
	uint32_t headers_len;
	FILE *fp;
	bfd_t *client_stream, *body_stream;

	headers = JS_ARGV(cx, vp)[0];
	path = JS_ARGV(cx, vp)[1];
	smtpClient = JS_THIS(cx, vp);

	// If no path, then use the default path where the body was saved
	if (argc == 1 || JSVAL_IS_NULL(path)) {
		jsval bodyStream;

		if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(smtpClient), "bodyStream", &bodyStream)) {
			return JS_FALSE;
		}

		body_stream = JSVAL_TO_PRIVATE(bodyStream);
	} else {
		c_path = JS_EncodeString(cx, JSVAL_TO_STRING(path));
		fp = fopen(c_path, "r");

		if (!fp) {
			JS_ReportError(js_context, "The file %s cannot be opened!", c_path);
			free(c_path);
			return JS_FALSE;
		}

		bodyfd = fileno(fp);

		if (bodyfd < 0) {
			JS_ReportError(js_context, "The file %s cannot be opened!", c_path);
			free(c_path);
			return JS_FALSE;
		}

		free(c_path);
		body_stream = bfd_alloc(bodyfd);
	}

	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(smtpClient), "clientStream", &clientStream)) {
		return JS_FALSE;
	}

	client_stream = JSVAL_TO_PRIVATE(clientStream);

	// Get number of headers
	if (!JS_GetArrayLength(cx, JSVAL_TO_OBJECT(headers), &headers_len)) {
		return JS_FALSE;
	}

	// Send headers
	for (i = 0; i < (int) headers_len; i++) {
		if (!JS_GetElement(cx, JSVAL_TO_OBJECT(headers), i, &rval)) {
			return -1;
		}

		jsval header;
		JS_CallFunctionName(cx, JSVAL_TO_OBJECT(rval), "toString",
				0, NULL, &header);

		c_header = JS_EncodeString(cx, JSVAL_TO_STRING(header));

		if (bfd_puts(client_stream, c_header) < 0) {
			free(c_header);
			bfd_close(client_stream);
			return JS_FALSE;
		}


		if (bfd_puts(client_stream, "\r\n") < 0) {
			free(c_header);
			bfd_close(client_stream);
			return JS_FALSE;
		}

		free(c_header);
	}

	if (bfd_puts(client_stream, "\r\n") < 0) {
		bfd_close(client_stream);
		return JS_FALSE;
	}

	// Put message body in the buffer
	if (bfd_puts(client_stream, body_stream->wb) < 0) {
		return JS_FALSE;
	}

	if (bfd_puts(client_stream, "\r\n.\r\n") < 0) {
		bfd_close(client_stream);
		return JS_FALSE;
	}


	// Flush message body
	bfd_flush(client_stream);

	return JS_TRUE;
}

static JSFunctionSpec SmtpClient_functions[] = {
	JS_FS("connect", SmtpClient_connect, 2, 0),
	JS_FS("readResponse", SmtpClient_readResponse, 0, 0),
	JS_FS("sendCommand", SmtpClient_sendCommand, 2, 0),
	JS_FS("sendMessageBody", SmtpClient_sendMessageBody, 2, 0),
	JS_FS_END
};

/* }}} SmtpClient */

/* {{{ SmtpServer */

static JSClass SmtpServer_class = {
	"SmtpServer", 0, JS_PropertyStub, JS_PropertyStub,
	JS_PropertyStub, JS_StrictPropertyStub, JS_EnumerateStub,
	JS_ResolveStub, JS_ConvertStub, NULL,
	JSCLASS_NO_OPTIONAL_MEMBERS
};

static JSBool SmtpServer_construct(JSContext *cx, unsigned argc, jsval *vp)
{
	JSObject *obj, *recipients, *headers;
	//jsval host, port, client;

	//host = JS_ARGV(cx, vp)[0];
	//port = JS_ARGV(cx, vp)[1];

	obj = JS_NewObjectForConstructor(cx, &SmtpServer_class, vp);
	if (!obj)
		return JS_FALSE;

	// Define and set session properties
	if (!JS_DefineProperty(cx, obj, "hostname", JSVAL_NULL, NULL, NULL, JSPROP_ENUMERATE))
		return JS_FALSE;

	if (!JS_DefineProperty(cx, obj, "envelopeSender", JSVAL_NULL, NULL, NULL, JSPROP_ENUMERATE))
		return JS_FALSE;

	recipients = JS_NewArrayObject(cx, 0, NULL);
	if (!recipients)
		return JS_FALSE;

	if (!JS_DefineProperty(cx, obj, "recipients", OBJECT_TO_JSVAL(recipients), NULL, NULL, JSPROP_ENUMERATE | JSPROP_PERMANENT))
		return JS_FALSE;

	headers = JS_NewArrayObject(cx, 0, NULL);
	if (!headers)
		return JS_FALSE;

	if (!JS_DefineProperty(cx, obj, "headers", OBJECT_TO_JSVAL(headers), NULL, NULL, JSPROP_ENUMERATE | JSPROP_PERMANENT))
		return JS_FALSE;

	if (!JS_DefineProperty(cx, obj, "quitAsserted", BOOLEAN_TO_JSVAL(JS_FALSE), NULL, NULL, JSPROP_ENUMERATE))
		return JS_FALSE;

	JS_SET_RVAL(cx, vp, OBJECT_TO_JSVAL(obj));
	return JS_TRUE;
}

#define DEFINE_HANDLER_STUB(name) \
	static JSBool smtp##name (JSContext *cx, unsigned argc, jsval *vp) { \
		jsval rval = create_response(cx, 250, "def" #name, 0); \
		JS_SET_RVAL(cx, vp, rval); \
		return JS_TRUE; \
	}

DEFINE_HANDLER_STUB(Init);
DEFINE_HANDLER_STUB(Auth);
DEFINE_HANDLER_STUB(Ehlo);
DEFINE_HANDLER_STUB(Helo);
DEFINE_HANDLER_STUB(Data);
DEFINE_HANDLER_STUB(Mail);
DEFINE_HANDLER_STUB(Rcpt);
DEFINE_HANDLER_STUB(Rset);
DEFINE_HANDLER_STUB(Body);
DEFINE_HANDLER_STUB(Clnp);

static JSFunctionSpec SmtpServer_functions[] = {
	JS_FS("smtpInit", smtpInit, 0, 0),
	JS_FS("smtpAuth", smtpAuth, 0, 0),
	JS_FS("smtpEhlo", smtpEhlo, 0, 0),
	JS_FS("smtpHelo", smtpHelo, 0, 0),
	JS_FS("smtpData", smtpData, 0, 0),
	JS_FS("smtpMail", smtpMail, 0, 0),
	JS_FS("smtpRcpt", smtpRcpt, 0, 0),
	JS_FS("smtpRset", smtpRset, 0, 0),
	JS_FS("smtpBody", smtpBody, 0, 0),
	JS_FS("smtpClnp", smtpClnp, 0, 0),
	JS_FS_END
};

/* }}} SmtpServer */

int js_smtp_init(JSContext *cx, JSObject *global)
{
	if (!JS_InitClass(cx, global, NULL, &SmtpPath_class, SmtpPath_construct, 1, NULL, SmtpPath_functions, NULL, NULL))
		return -1;

	if (!JS_InitClass(cx, global, NULL, &SmtpHeader_class, SmtpHeader_construct, 1, NULL, SmtpHeader_functions, NULL, NULL))
		return -1;

	if (!JS_InitClass(cx, global, NULL, &SmtpResponse_class, SmtpResponse_construct, 1, NULL, NULL, NULL, NULL))
		return -1;

	if (!JS_InitClass(cx, global, NULL, &SmtpClient_class, SmtpClient_construct, 1, NULL, SmtpClient_functions, NULL, NULL))
		return -1;

	if (!JS_InitClass(cx, global, NULL, &SmtpServer_class, SmtpServer_construct, 1, NULL, SmtpServer_functions, NULL, NULL))
		return -1;

	return 0;
}

// vim: foldmethod=marker
