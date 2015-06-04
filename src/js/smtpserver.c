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
	jsval path, mailbox, smtpPath, local;

	path = JS_ARGV(cx, vp)[0];

	char *c_str = JS_EncodeString(cx, JSVAL_TO_STRING(path));
	char *trailing = c_str;

	smtpPath = JS_THIS(cx, vp);

	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(smtpPath), "mailbox", &mailbox)) {
		return JS_FALSE;
	}

	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(mailbox), "local", &local)) {
		return JS_FALSE;
	}

	smtp_path_parse(&smtpPath, c_str, &trailing);

	JS_free(cx, c_str);

	return JS_TRUE;
}

static JSBool smtpPath_toString(JSContext *cx, unsigned argc, jsval *vp) {
	jsval path, domain, local, domains, smtpPath, mailbox;
	jsval rval;
	int str_len, domains_len, i;

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

	for (i = 0; i < domains_len; i++) {
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

	JS_SET_RVAL(cx, vp, STRING_TO_JSVAL(JS_InternString(cx, c_str)));
	return JS_TRUE;
}

int init_smtp_path_class(JSContext *cx, JSObject *global) {
	static JSClass smtpPath_class = {
	    "SmtpPath", 0,
	    JS_PropertyStub, JS_PropertyStub, JS_PropertyStub, JS_PropertyStub,
	    JS_EnumerateStub, JS_ResolveStub, JS_ConvertStub, JS_PropertyStub,
	    NULL, NULL, NULL, smtpPath_construct, NULL, NULL, NULL, NULL
	};

	JSObject *proto, *domains, *mailbox, *smtpPathClass;

	// Create the SmtpPath class
	smtpPathClass = JS_InitClass(cx, global, NULL, &smtpPath_class, smtpPath_construct, 1, NULL, NULL, NULL, NULL);

	if (!smtpPathClass) {
		return -1;
	}

	proto = JS_GetObjectPrototype(cx, smtpPathClass);

	// Add domains property
	domains = JS_NewArrayObject(cx, 0, NULL);

	if (!domains) {
		return -1;
	}

	if (!JS_DefineProperty(cx, proto, "domains", OBJECT_TO_JSVAL(domains), NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT)) {
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

	if (!JS_DefineProperty(cx, proto, "mailbox", OBJECT_TO_JSVAL(mailbox), NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT)) {
		return -1;
	}

	if (!JS_DefineFunction(cx, proto, "toString", smtpPath_toString, 0, 0)) {
		return -1;
	}

	return 0;
}

static JSBool header_construct(JSContext *cx, unsigned argc, jsval *vp) {
	return JS_TRUE;
}

static JSBool header_toString(JSContext *cx, unsigned argc, jsval *vp) {
	return JS_TRUE;
}

static JSBool header_getValue(JSContext *cx, unsigned argc, jsval *vp) {
	return JS_TRUE;
}

static JSBool header_refold(JSContext *cx, unsigned argc, jsval *vp) {
	return JS_TRUE;
}

int init_header_class(JSContext *cx, JSObject *global) {
	static JSClass header_class = {
	    "Header", 0,
	    JS_PropertyStub, JS_PropertyStub, JS_PropertyStub, JS_PropertyStub,
	    JS_EnumerateStub, JS_ResolveStub, JS_ConvertStub, JS_PropertyStub,
	    NULL, NULL, NULL, header_construct, NULL, NULL, NULL, NULL
	};

	// Create the SmtpPath class
	JSObject *headerClass = JS_InitClass(cx, global, NULL, &header_class, header_construct, 1, NULL, NULL, NULL, NULL);

	if (!headerClass) {
		return -1;
	}

	JSObject *proto = JS_GetObjectPrototype(cx, headerClass);

	// Define name property
	if (!JS_DefineProperty(cx, proto, "string", STRING_TO_JSVAL(JS_InternString(cx, "")), NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT)) {
		return -1;
	}

	// Define parts property
	JSObject *parts = JS_NewArrayObject(cx, 0, NULL);

	if (!parts) {
		return -1;
	}

	if (!JS_DefineProperty(cx, proto, "parts", OBJECT_TO_JSVAL(parts), NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT)) {
		return -1;
	}

	// Define other methods
	if (!JS_DefineFunction(cx, proto, "getValue", header_getValue, 0, 0)) {
		return -1;
	}

	if (!JS_DefineFunction(cx, proto, "toString", header_toString, 0, 0)) {
		return -1;
	}

	if (!JS_DefineFunction(cx, proto, "refold", header_refold, 1, 0)) {
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

	JSObject *smtpServer;

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

	// Create session object (property of smtpServer)
	JSObject *session;
	session = JS_NewObject(cx, NULL, NULL, NULL);

	// Define and set session.quitAsserted = false
	if (JS_DefineProperty(cx, session, "quitAsserted", BOOLEAN_TO_JSVAL(JS_FALSE), NULL, NULL, JSPROP_ENUMERATE) == JS_FALSE) {
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

