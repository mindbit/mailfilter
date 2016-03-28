#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <ctype.h>

#include "../config.h"
#include "js.h"
#include "engine.h"
#include "../string_tools.h"

JSContext *js_context;

static JSRuntime *rt;

/* The error reporter callback. */
static void reportError(JSContext *js_context, const char *message, JSErrorReport *report)
{
	fprintf(stderr, "%s:%u: error: %s\n", config.path,
			(unsigned int) report->lineno + 1, message);
}

jsval js_create_response(jsval *argv) {
	jsval response;
	JSObject *global;

	global = JS_GetGlobalForScopeChain(js_context);

	JS_CallFunctionName(js_context, global, "SmtpResponse",
				3, argv, &response);

	return response;
}

int js_get_code(jsval v) {
	jsval code;

	if (JS_GetProperty(js_context, JSVAL_TO_OBJECT(v), "code", &code)) {
		return JSVAL_TO_INT(code);
	}

	return -1;
}

char *js_get_message(jsval v) {
	jsval messages, msg, rval;
	uint32_t messages_len;
	char *c_str;
	int i;
	struct string_buffer sb = STRING_BUFFER_INITIALIZER;

	if (!JS_GetProperty(js_context, JSVAL_TO_OBJECT(v), "messages", &messages)) {
		return NULL;
	}

	switch(JS_TypeOfValue(js_context, messages)) {
		case JSTYPE_STRING:
			c_str = JS_EncodeString(js_context, JSVAL_TO_STRING(messages));
			return c_str;

		case JSTYPE_OBJECT:
			if (!JS_GetArrayLength(js_context, JSVAL_TO_OBJECT(messages), &messages_len)) {
				return NULL;
			}

			for (i = 0; i < (int) messages_len; i++) {
				if (!JS_GetElement(js_context, JSVAL_TO_OBJECT(messages), i, &msg)) {
					goto out_err;
				}

				c_str = JS_EncodeString(js_context, JSVAL_TO_STRING(msg));

				if (string_buffer_append_string(&sb, c_str))
					goto out_err;

				if (i < (int) messages_len - 1) {
					if (string_buffer_append_char(&sb, '\n'))
						goto out_err;
				}

				free(c_str);
			}

			return sb.s;
		default:
			break;
	}

out_err:
	free(c_str);
	string_buffer_cleanup(&sb);
	return NULL;
}

int js_get_disconnect(jsval v) {
	jsval disconnect;

	if (JS_GetProperty(js_context, JSVAL_TO_OBJECT(v), "disconnect", &disconnect)) {
		return JSVAL_TO_BOOLEAN(disconnect);
	}

	return 0;
}

int js_set_quitAsserted() {
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

	// Define and set session.quitAsserted = false
	if (JS_DefineProperty(js_context, JSVAL_TO_OBJECT(session), "quitAsserted", BOOLEAN_TO_JSVAL(JS_TRUE), NULL, NULL, JSPROP_ENUMERATE) == JS_FALSE) {
		return -1;
	}

	return 1;
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

int add_header_properties(jsval *header, jsval *name, jsval *parts_recv) {
	int i;
	uint32_t arr_len;
	JSObject *parts_obj;
	jsval parts;

	// Set name property
	if (!JS_SetProperty(js_context, JSVAL_TO_OBJECT(*header), "hname", name)) {
		return -1;
	}

	// Add parts property
	switch(JS_TypeOfValue(js_context, *parts_recv)) {
		case JSTYPE_STRING:
			// Create the messages array property
			parts_obj = JS_NewArrayObject(js_context, 0, NULL);

			if (!parts_obj) {
				return -1;
			}

			// Add message to messages array
			if (!JS_SetElement(js_context, parts_obj, 0, parts_recv)) {
				return -1;
			}

			// Copy the messages to the property
			parts = OBJECT_TO_JSVAL(parts_obj);

			if (!JS_SetProperty(js_context, JSVAL_TO_OBJECT(*header), "parts", &parts)) {
				return -1;
			}

			break;
		case JSTYPE_OBJECT:
			// Copy the messages to the property
			if (!JS_SetProperty(js_context, JSVAL_TO_OBJECT(*header), "parts", parts_recv)) {
				return -1;
			}
			break;
		default:
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

jsval call_js_handler(const char *cmd) {
    int i;
    char handler_name[9];

    strcpy(handler_name, "smtp");

    handler_name[4] = toupper((unsigned char) cmd[0]);

    for (i = 5; i < 8; i++) {
        handler_name[i] = tolower((unsigned char) cmd[i - 4]);
    }

    handler_name[8] = '\0';
        
    return js_call("smtpServer", handler_name, JSVAL_NULL);
}

jsval call_js_handler_with_arg(const char *cmd, char *arg) {
    int i;
    char handler_name[9];


    strcpy(handler_name, "smtp");

    handler_name[4] = toupper((unsigned char) cmd[0]);

    for (i = 5; i < 8; i++) {
        handler_name[i] = tolower((unsigned char) cmd[i - 4]);
    }

    handler_name[8] = '\0';

    jsval js_arg = STRING_TO_JSVAL(JS_InternString(js_context, arg));

    return js_call("smtpServer", handler_name, js_arg, JSVAL_NULL);
}

jsval js_call(const char *obj, const char *func, jsval arg, ...)
{
	JSObject *global, *curr_obj;

	/* Array which stores every "arg" parameter passed to the function */
	int argc = 0;
	jsval argv[16], curr_arg, rval;
	va_list ap;

	/* Used when fetching the given object from the global object */
	jsval objval;

	/* Build args array with arguments given to this function */
	va_start(ap, arg);
	curr_arg = arg;
	while (!JSVAL_IS_NULL(curr_arg)) {
		argv[argc++] = curr_arg;
		curr_arg = va_arg(ap, jsval);
	}
	va_end(ap);

	global = JS_GetGlobalForScopeChain(js_context);

	if (!JS_GetProperty(js_context, global, obj, &objval) ||
			JSVAL_IS_VOID(objval)) {
		fprintf(stderr, "%s: ERROR: object '%s' does not exist\n",
				__func__, obj);
		return JSVAL_NULL;
	}

	curr_obj = JSVAL_TO_OBJECT(objval);

	/* Get the property from object just to see if it exists */
	if (!JS_GetProperty(js_context, curr_obj, func, &objval) ||
			JSVAL_IS_VOID(objval)) {
		fprintf(stderr, "%s: ERROR: method '%s' not defined in '%s'\n",
				__func__, func, obj);
		return JSVAL_NULL;
	}

	/* Call the given function */
	if (!JS_CallFunctionName(js_context, curr_obj, func,
				argc, argv, &rval)) {
		fprintf(stderr, "%s: ERROR: failed calling '%s.%s()'\n",
				__func__, obj, func);
		return JSVAL_NULL;
	}

	return rval;
}

int js_init(const char *filename)
{
	JSObject *global;

	int fd;
	void *buf;
	off_t len;

	/* The class of the global object. */
	static JSClass global_class = {
		"global", JSCLASS_GLOBAL_FLAGS, JS_PropertyStub,
		JS_PropertyStub, JS_PropertyStub, JS_StrictPropertyStub,
		JS_EnumerateStub, JS_ResolveStub, JS_ConvertStub,
		JS_PropertyStub, JSCLASS_NO_OPTIONAL_MEMBERS
	};

	/* Create a JS runtime. You always need at least one runtime per process. */
	rt = JS_NewRuntime(8 * 1024 * 1024);
	if (rt == NULL)
		return -1;
	/*
	 * Create a context. You always need a context per thread.
	 * Note that this program is not multi-threaded.
	 */
	js_context = JS_NewContext(rt, 8192);
	if (js_context == NULL)
		return -1;
	JS_SetOptions(js_context, JSOPTION_VAROBJFIX | JSOPTION_METHODJIT);
	JS_SetVersion(js_context, JSVERSION_LATEST);
	JS_SetErrorReporter(js_context, reportError);

	/*
	 * Create the global object in a new compartment.
	 * You always need a global object per context.
	 */
	global = JS_NewGlobalObject(js_context, &global_class, NULL);
	if (global == NULL)
		return -1;

	/*
	 * Populate the global object with the standard JavaScript
	 * function and object classes, such as Object, Array, Date.
	 */
	if (!JS_InitStandardClasses(js_context, global))
		return -1;

	/* Read the file into memory */
	fd = open(filename, O_RDONLY, 0);
	if (fd < 0) {
		perror(filename);
		return -1;
	}

	len = lseek(fd, 0, SEEK_END);
	if (len == (off_t) -1) {
		close(fd);
		perror("lseek");
		return -1;
	}

	buf = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		close(fd);
		perror("mmap");
		return -1;
	}

	/* Initialize global objects */
	if (js_engine_obj_init(js_context, global))
		return -1;
	if (js_smtp_server_obj_init(js_context, global))
		return -1;

	/* Run script */
	JS_EvaluateScript(js_context, global, buf, len, filename, 0, NULL);

	/* Evaluate the changes caused by the script */
	if (js_engine_parse(js_context, global))
		return -1;

	return 0;
}

void js_stop(void)
{
	/* Clean things up and shut down SpiderMonkey. */
	JS_DestroyContext(js_context);
	JS_DestroyRuntime(rt);
	JS_ShutDown();
}
