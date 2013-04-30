#include "engine.h"
#include "../config.h"

/* Function Summary */
/*
 * PROPERTY HANDLERS:
 *
 * 1. logging_hdlr()
 *	- Handles the object passed to the 'logging' property.
 *
 * NATIVE FUNCTIONS:
 *
 * 1. load_module()
 *	- Implementation of the "engine.loadModule()" function.
 */

/* FIXME: Print appropriate errors when bad values are given */
static JSBool logging_hdlr(JSContext *cx, JSObject *obj, jsval *vp)
{
	JSObject *logging_obj;
	jsval property_value;
	JSString *property_str;
	char *property_arr;

	/* Check if an object is assigned to 'logging' property */
	if (JSVAL_IS_PRIMITIVE(*vp))
		return JS_FALSE;

	/* Get the value of the 'type' property */
	logging_obj = JSVAL_TO_OBJECT(*vp);
	if (!JS_GetProperty(cx, logging_obj, "type", &property_value))
		return JS_FALSE;

	if (property_value == JSVAL_VOID)
		goto level; /* type not specified, jump to level */

	if (!JSVAL_IS_STRING(property_value))
		return JS_FALSE;
	property_str = JSVAL_TO_STRING(property_value);
	property_arr = JS_EncodeString(cx, property_str);

	/* Check if 'type' has a valid value (syslog, stderr, logfile) */
	if (str_2_val(log_types, property_arr) < 0)
		return JS_FALSE;

	config.logging_type = str_2_val(log_types, property_arr);
	JS_free(cx, property_arr);


level:
	/* Get the value of the 'level' property */
	logging_obj = JSVAL_TO_OBJECT(*vp);
	if (!JS_GetProperty(cx, logging_obj, "level", &property_value))
		return JS_FALSE;

	if (property_value == JSVAL_VOID)
		goto facility; /* level not specified, jump to facility */

	if (!JSVAL_IS_STRING(property_value))
		return JS_FALSE;
	property_str = JSVAL_TO_STRING(property_value);
	property_arr = JS_EncodeString(cx, property_str);

	/* Check if 'level' has a valid value (LOG_EMERG, LOG_ALERT, etc.) */
	if (str_2_val(log_levels, property_arr) < 0)
		return JS_FALSE;

	config.logging_level = str_2_val(log_levels, property_arr);
	JS_free(cx, property_arr);


facility:
	/* Get the value of the 'facility' property */
	logging_obj = JSVAL_TO_OBJECT(*vp);
	if (!JS_GetProperty(cx, logging_obj, "facility", &property_value))
		return JS_FALSE;

	if (property_value == JSVAL_VOID)
		return JS_TRUE; /* facility not specified, leave it default */

	if (!JSVAL_IS_STRING(property_value))
		return JS_FALSE;
	property_str = JSVAL_TO_STRING(property_value);
	property_arr = JS_EncodeString(cx, property_str);

	/* Check if 'facility' has a valid value (LOG_EMERG, LOG_ALERT, etc.) */
	if (str_2_val(log_facilities, property_arr) < 0)
		return JS_FALSE;

	config.logging_facility = str_2_val(log_facilities, property_arr);
	JS_free(cx, property_arr);

	return JS_TRUE;
}

static JSObject *engine;

static JSBool load_module(JSContext *cx, unsigned argc, jsval *vp)
{
	jsval module;
	JSString *module_str;
	char *module_name;

	module = JS_ARGV(cx, vp)[0];

	if (!JSVAL_IS_STRING(module))
		return JS_FALSE;

	module_str = JSVAL_TO_STRING(module);
	module_name = JS_EncodeString(cx, module_str);
	if (!module_name)
		return JS_FALSE;

	printf("[STUB] Loading module \"%s\".\n", module_name);

	JS_free(cx, module_name);
	return JS_TRUE;
}

int js_engine_parse(JSContext *cx, JSObject *global)
{
	jsval engine_val, logging_val;

	if (!JS_GetProperty(cx, global, "engine", &engine_val))
		return -1;
	engine = JSVAL_TO_OBJECT(engine_val);

	/* Parse 'logging' property. */
	if (!JS_GetProperty(cx, engine, "logging", &logging_val))
		return -1;

	if (logging_hdlr(cx, global, &logging_val))
		return -1;

	return 0;
}

static JSClass engine_class = {
	"engine", 0, JS_PropertyStub, JS_PropertyStub, JS_PropertyStub,
	JS_StrictPropertyStub, JS_EnumerateStub, JS_ResolveStub,
	JS_ConvertStub, JS_FinalizeStub, JSCLASS_NO_OPTIONAL_MEMBERS
};

int js_engine_obj_init(JSContext *cx, JSObject *global)
{

	engine = JS_DefineObject(cx, global, "engine", &engine_class, NULL, 0);
	if (!engine)
		return -1;

	if (!JS_DefineFunction(cx, engine, "loadModule", load_module, 1, 0))
		return -1;

	return 0;
}
