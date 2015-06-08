#include "smtpserver.h"

DEFINE_HANDLER_STUB(Init);
DEFINE_HANDLER_STUB(Auth);
DEFINE_HANDLER_STUB(Alou);
DEFINE_HANDLER_STUB(Alop);
DEFINE_HANDLER_STUB(Ehlo);
DEFINE_HANDLER_STUB(Data);
DEFINE_HANDLER_STUB(Mail);
DEFINE_HANDLER_STUB(Rcpt);
DEFINE_HANDLER_STUB(Rset);
DEFINE_HANDLER_STUB(Body);
DEFINE_HANDLER_STUB(Clnp);

jsval create_response(JSContext *cx, int code, const char* message, int disconnect) { 
	jsval rmessage;
	JSObject *obj;
	
	obj = JS_NewObject(cx, NULL, NULL, NULL);
	
	if (message != NULL) {
		rmessage = STRING_TO_JSVAL(JS_InternString(cx, message));
	} else {
		// TODO
		// define message property with default value for current code
		rmessage = STRING_TO_JSVAL(JS_InternString(cx, "default err message"));
	}
	
	JS_DefineProperty(cx, obj, "code", INT_TO_JSVAL(code), NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT);
	
	JS_DefineProperty(cx, obj, "message", rmessage, NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT);
	
	JS_DefineProperty(cx, obj, "disconnect", INT_TO_JSVAL(disconnect), NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT);
	
	return OBJECT_TO_JSVAL(obj);
}

static JSBool smtpPath_construct(JSContext *cx, unsigned argc, jsval *vp) {
	jsval path, smtpPath;
	JSObject *domains, *mailbox, *smtpPath_obj;

	path = JS_ARGV(cx, vp)[0];

	char *c_str = JS_EncodeString(cx, JSVAL_TO_STRING(path));
	char *trailing = c_str;

	smtpPath_obj = JS_NewObject(cx, 0, 0, 0);

	// Add toString method
	if (!JS_DefineFunction(cx, smtpPath_obj, "toString", smtpPath_toString, 0, 0)) {
		return -1;
	}

	// Add domains property
	domains = JS_NewArrayObject(cx, 0, NULL);

	if (!domains) {
		return -1;
	}

	if (!JS_DefineProperty(cx, smtpPath_obj, "domains", OBJECT_TO_JSVAL(domains), NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT)) {
		return -1;
	}

	// Add mailbox property
	mailbox = JS_NewObject(cx, NULL, NULL, NULL);

	if (!mailbox) {
		return -1;
	}

	if (!JS_DefineProperty(cx, mailbox, "local", STRING_TO_JSVAL(JS_InternString(cx, "")), NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT)) {
		return -1;
	}

	if (!JS_DefineProperty(cx, mailbox, "domain", STRING_TO_JSVAL(JS_InternString(cx, "")), NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT)) {
		return -1;
	}

	if (!JS_DefineProperty(cx, smtpPath_obj, "mailbox", OBJECT_TO_JSVAL(mailbox), NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT)) {
		return -1;
	}

	smtpPath = OBJECT_TO_JSVAL(smtpPath_obj);

	smtp_path_parse(&smtpPath, c_str, &trailing);

	JS_free(cx, c_str);

	JS_SET_RVAL(cx, vp, smtpPath);
	return JS_TRUE;
}

static JSBool smtpPath_toString(JSContext *cx, unsigned argc, jsval *vp) {
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

int init_smtp_path_class(JSContext *cx, JSObject *global) {
	static JSClass smtpPath_class = {
	    "SmtpPath", 0,
	    JS_PropertyStub, JS_PropertyStub, JS_PropertyStub, JS_PropertyStub,
	    JS_EnumerateStub, JS_ResolveStub, JS_ConvertStub, JS_PropertyStub,
	    NULL, NULL, NULL, smtpPath_construct, NULL, NULL, NULL, NULL
	};

	JSObject *smtpPathClass;

	// Create the SmtpPath class
	smtpPathClass = JS_InitClass(cx, global, NULL, &smtpPath_class, smtpPath_construct, 1, NULL, NULL, NULL, NULL);

	if (!smtpPathClass) {
		return -1;
	}

	return 0;
}

static JSBool header_toString(JSContext *cx, unsigned argc, jsval *vp) {

	jsval value, rval, hname;

	jsval header = JS_THIS(cx, vp);

	// Get name
	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(header), "hname", &hname)) {
		return JS_FALSE;
	}


	// Get value
	if (header_getValue(cx, argc, vp)) {
		value = *vp;
	}

	rval = STRING_TO_JSVAL(JS_ConcatStrings(cx, JSVAL_TO_STRING(hname), JS_InternString(cx, ": ")));
	rval = STRING_TO_JSVAL(JS_ConcatStrings(cx, JSVAL_TO_STRING(rval), JSVAL_TO_STRING(value)));

	JS_SET_RVAL(cx, vp, rval);
	return JS_TRUE;
}

static JSBool header_getValue(JSContext *cx, unsigned argc, jsval *vp) {
	jsval parts, rval;

	jsval header = JS_THIS(cx, vp);
	uint32_t parts_len;
	int i;

	// Get domains
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

	char *c_str;
	char *header_len = 0;

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

	strcpy(c_str, JS_EncodeString(cx, JSVAL_TO_STRING(rval)));
	strcat(c_str, "\r\n");

	for (i = 1; i < (int) parts_len; i++) {
		if (!JS_GetElement(cx, JSVAL_TO_OBJECT(parts), i, &rval)) {
			return -1;
		}

		strcat(c_str, JS_EncodeString(cx, JSVAL_TO_STRING(rval)));

		if (i < (int) (parts_len - 1)) {
			strcat(c_str, "\r\n");
		}
	}

	strcat(c_str, "\0");

	JS_SET_RVAL(cx, vp, STRING_TO_JSVAL(JS_InternString(cx, c_str)));

	free(c_str);

	return JS_TRUE;
}

static JSBool header_getValue(JSContext *cx, unsigned argc, jsval *vp) {
	return JS_TRUE;
}

static JSBool header_construct(JSContext *cx, unsigned argc, jsval *vp) {
	jsval name, parts_recv, header;
	JSObject *header_obj

	name = JS_ARGV(cx, vp)[0];
	parts_recv = JS_ARGV(cx, vp)[1];

	header_obj = JS_NewObject(cx, 0, 0, 0);
	header = OBJECT_TO_JSVAL(header_obj);

	// Add getStrng method
	if (!JS_DefineFunction(cx, header_obj, "toString", header_toString, 0, 0)) {
		return -1;
	}

	// Add getValue method
	if (!JS_DefineFunction(cx, header_obj, "getValue", header_getValue, 0, 0)) {
		return -1;
	}

	// Add refold method
	if (!JS_DefineFunction(cx, header_obj, "refold", header_refold, 0, 0)) {
		return -1;
	}

	add_header_properties(&header, &name, &parts_recv);

	JS_SET_RVAL(cx, vp, header);
	return JS_TRUE;
}

int init_header_class(JSContext *cx, JSObject *global) {
	static JSClass header_class = {
	    "Header", 0,
	    JS_PropertyStub, JS_PropertyStub, JS_PropertyStub, JS_PropertyStub,
	    JS_EnumerateStub, JS_ResolveStub, JS_ConvertStub, JS_PropertyStub,
	    NULL, NULL, NULL, header_construct, NULL, NULL, NULL, NULL
	};

	JSObject *headerClass;

	JSFunctionSpec smtp_header_methods[] = {
		JS_FS("getString", header_toString, 0, 0),
		JS_FS("getValue", header_getValue, 0, 0),
		JS_FS("refold", header_refold, 0, 0),
		JS_FS_END
	};

	// Create the SmtpPath class
	headerClass = JS_InitClass(cx, global, NULL, &header_class, header_construct, 1, NULL, &smtp_header_methods, NULL, NULL);

	if (!headerClass) {
		return -1;
	}

	return 0;
}

int js_smtp_server_obj_init(JSContext *cx, JSObject *global)
{
	static JSClass smtpserver_class = {
		"smtpServer", 0, JS_PropertyStub, JS_PropertyStub,
		JS_PropertyStub, JS_StrictPropertyStub, JS_EnumerateStub,
		JS_ResolveStub, JS_ConvertStub, JS_PropertyStub,
		JSCLASS_NO_OPTIONAL_MEMBERS
	};

	JSObject *smtpServer, *session, *recipients, *headers;

	smtpServer = JS_DefineObject(cx, global, "smtpServer", &smtpserver_class, NULL, 0);
	if (!smtpServer)
		return -1;

	JSFunctionSpec smtp_command_handlers[] = {
		JS_FS("smtpInit", smtpInit, 0, 0),
		JS_FS("smtpAuth", smtpAuth, 0, 0),
		JS_FS("smtpAlou", smtpAlou, 0, 0),
		JS_FS("smtpAlop", smtpAlop, 0, 0),
		JS_FS("smtpEhlo", smtpEhlo, 0, 0),
		JS_FS("smtpData", smtpData, 0, 0),
		JS_FS("smtpMail", smtpMail, 0, 0),
		JS_FS("smtpRcpt", smtpRcpt, 0, 0),
		JS_FS("smtpRset", smtpRset, 0, 0),
		JS_FS("smtpBody", smtpBody, 0, 0),
		JS_FS("smtpClnp", smtpClnp, 0, 0),
		JS_FS_END
	};

	if (JS_DefineFunctions(cx, smtpServer, smtp_command_handlers) == JS_FALSE) {
		return -1;
	}

	session = JS_NewObject(cx, NULL, NULL, NULL);

	// Define and set session properties
	if (JS_DefineProperty(cx, session, "quitAsserted", BOOLEAN_TO_JSVAL(JS_FALSE), NULL, NULL, JSPROP_ENUMERATE) == JS_FALSE) {
		return -1;
	}

	if (JS_DefineProperty(cx, session, "envelopeSender", JSVAL_NULL, NULL, NULL, JSPROP_ENUMERATE) == JS_FALSE) {
		return -1;
	}

	// Add domains property
	recipients = JS_NewArrayObject(cx, 0, NULL);

	if (!recipients) {
		return -1;
	}

	if (!JS_DefineProperty(cx, session, "recipients", OBJECT_TO_JSVAL(recipients), NULL, NULL, JSPROP_ENUMERATE | JSPROP_PERMANENT)) {
		return -1;
	}

	// Add headers property
	headers = JS_NewArrayObject(cx, 0, NULL);

	if (!headers) {
		return -1;
	}

	if (!JS_DefineProperty(cx, session, "headers", OBJECT_TO_JSVAL(headers), NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT)) {
		return -1;
	}

	// Define smtpServer.session
	if (JS_DefineProperty(cx, smtpServer, "session", OBJECT_TO_JSVAL(session), NULL, NULL, JSPROP_ENUMERATE) == JS_FALSE) {
		return -1;
	}

	if (init_smtp_path_class(cx, global)) {
		return -1;
	}

	if (init_header_class(cx, global)) {
		return -1;
	}

	return 0;
}

