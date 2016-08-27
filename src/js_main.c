#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <jsmisc.h>

#include "js_main.h"
#include "string_tools.h"

extern JSContext *js_context; // FIXME pass through arguments

jsval js_create_response(jsval *argv) {
	jsval response;
	JSObject *global;

	global = JS_GetGlobalForScopeChain(js_context);

	JS_CallFunctionName(js_context, global, "SmtpResponse",
				3, argv, &response);

	return response;
}

int add_body_stream(bfd_t *body_stream) {
	jsval smtpClient, bodyStream;
	JSObject *global;

	global = JS_GetGlobalForScopeChain(js_context);

	// Get smtpClient
	if (!JS_GetProperty(js_context, global, "smtpClient", &smtpClient)) {
		return -1;
	}

	bodyStream = PRIVATE_TO_JSVAL(body_stream);

	// Add path property
	if (!JS_SetProperty(js_context, JSVAL_TO_OBJECT(smtpClient), "bodyStream", &bodyStream)) {
		return -1;
	}

	return 0;
}

int add_path_local(jsval *smtpPath, char *local) {
	jsval mailbox;

	// Get smtpPath.mailbox property
	if (JS_GetProperty(js_context, JSVAL_TO_OBJECT(*smtpPath), "mailbox", &mailbox) == JS_FALSE) {
		return -1;
	}

	// Set smtpPath.local
	if (!JS_DefineProperty(js_context, JSVAL_TO_OBJECT(mailbox), "local", STRING_TO_JSVAL(JS_InternString(js_context, local)), NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT)) {
		return -1;
	}

	return 0;
}

int add_path_domain(jsval *smtpPath, char *domain) {
	jsval mailbox;

	// Get smtpPath.mailbox property
	if (!JS_GetProperty(js_context, JSVAL_TO_OBJECT(*smtpPath), "mailbox", &mailbox)) {
		return -1;
	}

	// Set smtpPath.local
	if (!JS_DefineProperty(js_context, JSVAL_TO_OBJECT(mailbox), "domain", STRING_TO_JSVAL(JS_InternString(js_context, domain)), NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT)) {
		return -1;
	}

	return 0;
}

int add_domain(jsval *smtpPath, char *domain) {
	jsval domains;
	uint32_t arr_len;

	// Get smtpPath.domains property
	if (!JS_GetProperty(js_context, JSVAL_TO_OBJECT(*smtpPath), "domains", &domains)) {
		return -1;
	}

	// Get number of recipients
	if (!JS_GetArrayLength(js_context, JSVAL_TO_OBJECT(domains), &arr_len)) {
		return -1;
	}

	// Add recipient
	if (!JS_DefineElement(js_context, JSVAL_TO_OBJECT(domains), arr_len, STRING_TO_JSVAL(JS_InternString(js_context, domain)), NULL, NULL, 0)) {
		return -1;
	}

	return 0;
}

int set_envelope_sender(jsval *smtpPath) {
	jsval session, smtpServer;
	JSObject *global;

	global = JS_GetGlobalForScopeChain(js_context);

	// Get smtpServer
	if (!JS_GetProperty(js_context, global, "smtpServer", &smtpServer)) {
		return -1;
	}

	// Get session
	if (!JS_GetProperty(js_context, JSVAL_TO_OBJECT(smtpServer), "session", &session)) {
		return -1;
	}

	// Set session.envelopeSender
	if (!JS_SetProperty(js_context, JSVAL_TO_OBJECT(session), "envelopeSender", smtpPath)) {
		return -1;
	}

	return 0;
}

int add_recipient(jsval *smtpPath) {
	jsval session, smtpServer, recipients;
	JSObject *global;

	global = JS_GetGlobalForScopeChain(js_context);
	uint32_t arr_len;

	// Get smtpServer
	if (!JS_GetProperty(js_context, global, "smtpServer", &smtpServer)) {
		return -1;
	}

	// Get session
	if (!JS_GetProperty(js_context, JSVAL_TO_OBJECT(smtpServer), "session", &session)) {
		return -1;
	}

	// Get current recipients
	if (!JS_GetProperty(js_context, JSVAL_TO_OBJECT(session), "recipients", &recipients)) {
		return -1;
	}

	// Get number of recipients
	if (!JS_GetArrayLength(js_context, JSVAL_TO_OBJECT(recipients), &arr_len)) {
		return -1;
	}

	// Add recipient
	if (!JS_DefineElement(js_context, JSVAL_TO_OBJECT(recipients), arr_len, *smtpPath, NULL, NULL, 0)) {
		return -1;
	}

	return 0;
}

jsval new_smtp_path_instance(char *arg) {
	jsval path, session, smtpPathClass, smtpServer;
	JSObject *global;

	global = JS_GetGlobalForScopeChain(js_context);

	// Get smtpServer
	if (!JS_GetProperty(js_context, global, "smtpServer", &smtpServer)) {
		return JSVAL_NULL;
	}

	// Get session
	if (!JS_GetProperty(js_context, JSVAL_TO_OBJECT(smtpServer), "session", &session)) {
		return JSVAL_NULL;
	}

	// Get smtpPathClass
	if (!JS_GetProperty(js_context, global, "SmtpPath", &smtpPathClass)) {
		return JSVAL_NULL;
	}


	jsval argv = STRING_TO_JSVAL(JS_InternString(js_context, arg));

	JS_CallFunctionName(js_context, global, "SmtpPath",
				1, &argv, &path);

	return path;
}

int add_new_header(jsval *header) {
	jsval session, smtpServer, headers;
	JSObject *global;
	uint32_t arr_len;

	global = JS_GetGlobalForScopeChain(js_context);

	// Get smtpServer
	if (!JS_GetProperty(js_context, global, "smtpServer", &smtpServer)) {
		return -1;
	}

	// Get session
	if (!JS_GetProperty(js_context, JSVAL_TO_OBJECT(smtpServer), "session", &session)) {
		return -1;
	}

	// Get session
	if (!JS_GetProperty(js_context, JSVAL_TO_OBJECT(session), "headers", &headers)) {
		return -1;
	}

	// Get number of headers
	if (!JS_GetArrayLength(js_context, JSVAL_TO_OBJECT(headers), &arr_len)) {
		return -1;
	}

	// Add header
	if (!JS_SetElement(js_context, JSVAL_TO_OBJECT(headers), arr_len, header)) {
		return -1;
	}

	return 0;
}

jsval new_header_instance(char *name) {
	jsval header, js_name;
	JSObject *global, *parts_obj;

	global = JS_GetGlobalForScopeChain(js_context);

	js_name = STRING_TO_JSVAL(JS_InternString(js_context, name));

	parts_obj = JS_NewArrayObject(js_context, 0, NULL);

	jsval js_parts = OBJECT_TO_JSVAL(parts_obj);

	jsval argv[2] = {js_name, js_parts};

	JS_CallFunctionName(js_context, global, "Header",
				2, argv, &header);

	return header;
}

int add_part_to_header(jsval *header, char *c_str) {
	jsval part, parts;
	uint32_t parts_len;

	// Get parts array
	if (!JS_GetProperty(js_context, JSVAL_TO_OBJECT(*header), "parts", &parts)) {
		return 1;
	}

	// Get parts count
	if (!JS_GetArrayLength(js_context, JSVAL_TO_OBJECT(parts), &parts_len)) {
		return 1;
	}

	part = STRING_TO_JSVAL(JS_InternString(js_context, c_str));

	// Add part to array
	if (!JS_SetElement(js_context, JSVAL_TO_OBJECT(parts), parts_len, &part)) {
		return -1;
	}

	return 0;
}
