#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <jsmisc.h>

#include "js_main.h"
#include "js_smtp.h"
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
	if (!JS_GetProperty(js_context, JSVAL_TO_OBJECT(session), PR_HEADERS, &headers)) {
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
