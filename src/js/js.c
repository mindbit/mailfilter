#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../config.h"
#include "js.h"
#include "engine.h"

JSContext *js_context;

static JSRuntime *rt;

/* The error reporter callback. */
static void reportError(JSContext *js_context, const char *message, JSErrorReport *report)
{
	fprintf(stderr, "%s:%u: error: %s\n", config.path,
			(unsigned int) report->lineno + 1, message);
}

void js_dump_array(JSContext *cx, jsval v) {
	jsval val;

	if (JS_GetProperty(cx, JSVAL_TO_OBJECT(v), JS_EncodeString(cx, JS_InternString(cx, "0")), &val)) {
		printf("arr[0] = ");
		js_dump_value(cx, val);
	}

	if (JS_GetProperty(cx, JSVAL_TO_OBJECT(v), JS_EncodeString(cx, JS_InternString(cx, "1")), &val)) {
		printf("arr[1] = ");
		js_dump_value(cx, val);
	}

}

void js_dump_value(JSContext *cx, jsval v)
{
	char *c_str;

	switch (JS_TypeOfValue(cx, v)) {
		case JSTYPE_OBJECT:
			if (JSVAL_IS_NULL(v)) {
				printf("NULL\n");
				break;
			}
			if (JS_IsArrayObject(cx, JSVAL_TO_OBJECT(v))) {
				js_dump_array(cx, v);
				break;
			}
			printf("OBJECT {\n");
			printf("}\n");
			break;
		case JSTYPE_STRING:
			c_str = JS_EncodeString(cx, JSVAL_TO_STRING(v));
			printf("STRING(%zu) \"%s\"\n", strlen(c_str), c_str);
			JS_free(cx, c_str);
			break;
		case JSTYPE_NUMBER:
			printf("NUMBER(%d)\n", JSVAL_TO_INT(v));
			break;
		default:
			printf("FIXME\n");
			break;
	}
}

char* format_func_name(const char *func) {
        int i;
        char* func_name = malloc(9 * sizeof(char));

        strcpy(func_name, "smtp");
        
        func_name[4] = func[0];
        
        for (i = 5; i < 8; i++) {
            func_name[i] = tolower((unsigned char) func[i - 4]);
        }

        func_name[8] = '\0';
        
        return func_name;
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

	js_dump_value(js_context, rval);

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
