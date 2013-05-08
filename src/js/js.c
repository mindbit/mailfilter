#include <fcntl.h>
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
	fprintf(stderr, "%s:%u: error: %s\n",
			config.path,
			(unsigned int) report->lineno + 1,
			message);
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
		JS_FinalizeStub, JSCLASS_NO_OPTIONAL_MEMBERS
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
	JS_SetOptions(js_context, JSOPTION_VAROBJFIX | JSOPTION_JIT | JSOPTION_METHODJIT);
	JS_SetVersion(js_context, JSVERSION_LATEST);
	JS_SetErrorReporter(js_context, reportError);

	/*
	 * Create the global object in a new compartment.
	 * You always need a global object per context.
	 */
	global = JS_NewCompartmentAndGlobalObject(js_context, &global_class, NULL);
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
