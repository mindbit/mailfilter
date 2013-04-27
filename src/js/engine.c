#include "engine.h"

static JSClass engine_class = {
	"engine", JSCLASS_GLOBAL_FLAGS,
	JS_PropertyStub, JS_PropertyStub, JS_PropertyStub, JS_StrictPropertyStub,
	JS_EnumerateStub, JS_ResolveStub, JS_ConvertStub, JS_FinalizeStub,
	JSCLASS_NO_OPTIONAL_MEMBERS
};

static JSObject *engine;

int js_engine_obj_init(JSContext *cx, JSObject *global)
{
	engine = JS_DefineObject(cx, global, "engine", &engine_class, NULL, 0);
	if (engine == NULL)
		return -1;

	return 0;
}
