#include "js.h"

#include "engine.h"

#define TEST_SCRIPT \
	"engine.logging = {		\n"\
		"type: \"syslog\",	\n"\
		"level: \"debug\",	\n"\
		"facility: \"mail\"	\n"\
	"};				\n"

/* The class of the global object. */
static JSClass global_class = {
	"global", JSCLASS_GLOBAL_FLAGS, JS_PropertyStub, JS_PropertyStub,
	JS_PropertyStub, JS_StrictPropertyStub, JS_EnumerateStub,
	JS_ResolveStub, JS_ConvertStub, JS_FinalizeStub,
	JSCLASS_NO_OPTIONAL_MEMBERS
};

/* JSAPI variables. */
static JSContext *cx;
static JSRuntime *rt;

/* The error reporter callback. */
static void reportError(JSContext *cx, const char *message, JSErrorReport *report)
{
	fprintf(stderr, "%s:%u:%s\n",
			report->filename ? report->filename : "<no filename=\"filename\">",
			(unsigned int) report->lineno,
			message);
}

int js_init(void)
{
	JSObject *global;

	/* Create a JS runtime. You always need at least one runtime per process. */
	rt = JS_NewRuntime(8 * 1024 * 1024);
	if (rt == NULL)
		return -1;
	/*
	 * Create a context. You always need a context per thread.
	 * Note that this program is not multi-threaded.
	 */
	cx = JS_NewContext(rt, 8192);
	if (cx == NULL)
		return -1;
	JS_SetOptions(cx, JSOPTION_VAROBJFIX | JSOPTION_JIT | JSOPTION_METHODJIT);
	JS_SetVersion(cx, JSVERSION_LATEST);
	JS_SetErrorReporter(cx, reportError);

	/*
	 * Create the global object in a new compartment.
	 * You always need a global object per context.
	 */
	global = JS_NewCompartmentAndGlobalObject(cx, &global_class, NULL);
	if (global == NULL)
		return -1;

	/*
	 * Populate the global object with the standard JavaScript
	 * function and object classes, such as Object, Array, Date.
	 */
	if (!JS_InitStandardClasses(cx, global))
		return -1;

	/* Initialize objects */
	if (js_engine_obj_init(cx, global))
		return -1;

	/* TODO: Use real script file, not just a test script. */
	JS_EvaluateScript(cx, global, TEST_SCRIPT, strlen(TEST_SCRIPT),
			"none", 0, NULL);
	return 0;
}

void js_stop(void)
{
	JS_DestroyContext(cx);
	JS_DestroyRuntime(rt);
	JS_ShutDown();
}
