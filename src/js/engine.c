#include "engine.h"
#include "../config.h"

/* Function Summary */
/*
 * 1. add_prop_hdlr()
 *	- Called whenever a property is added to the 'engine' object.
 *
 * 1.1. logging_prop_hdlr()
 *	- Handles the object passed to the 'logging' property.
 */

/* FIXME: Print appropriate errors when bad values are given */
static JSBool logging_prop_hdlr(JSContext *cx, JSObject *obj, jsval *vp)
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

	if (!JSVAL_IS_STRING(property_value))
		return JS_FALSE;
	property_str = JSVAL_TO_STRING(property_value);
	property_arr = JS_EncodeString(cx, property_str);

	/* Check if 'type' has a valid value (syslog, stderr, logfile) */
	if (str_2_val(log_types, property_arr) < 0)
		return JS_FALSE;

	config.logging_type = str_2_val(log_types, property_arr);
	JS_free(cx, property_arr);


	/* Get the value of the 'level' property */
	logging_obj = JSVAL_TO_OBJECT(*vp);
	if (!JS_GetProperty(cx, logging_obj, "level", &property_value))
		return JS_FALSE;

	if (!JSVAL_IS_STRING(property_value))
		return JS_FALSE;
	property_str = JSVAL_TO_STRING(property_value);
	property_arr = JS_EncodeString(cx, property_str);

	/* Check if 'level' has a valid value (LOG_EMERG, LOG_ALERT, etc.) */
	if (str_2_val(log_levels, property_arr) < 0)
		return JS_FALSE;

	config.logging_level = str_2_val(log_levels, property_arr);
	JS_free(cx, property_arr);


	/* Get the value of the 'facility' property */
	logging_obj = JSVAL_TO_OBJECT(*vp);
	if (!JS_GetProperty(cx, logging_obj, "facility", &property_value))
		return JS_FALSE;

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

static JSBool add_prop_hdlr(JSContext *cx, JSObject *obj, jsid id, jsval *vp)
{
	jsval property;
	JSString *property_str;
	char *property_arr;

	/*
	 * Some sanity checks to see if there was actually a new property
	 * created on the 'engine' object.
	 */
	if (!JS_IdToValue(cx, id, &property))
		return JS_FALSE;

	if (!JSVAL_IS_STRING(property))
		return JS_FALSE;

	property_str = JSVAL_TO_STRING(property);
	if (!property_str)
		return JS_FALSE;

	property_arr = JS_EncodeString(cx, property_str);
	if (!property_arr)
		return JS_FALSE;

	/* Handle 'logging' property assignment here */
	if (strcmp(property_arr, "logging") == 0)
		return logging_prop_hdlr(cx, obj, vp);

	JS_free(cx, property_arr);
	return JS_TRUE;
}

static JSClass engine_class = {
	"engine", JSCLASS_GLOBAL_FLAGS, add_prop_hdlr, JS_PropertyStub,
	JS_PropertyStub, JS_StrictPropertyStub, JS_EnumerateStub,
	JS_ResolveStub, JS_ConvertStub, JS_FinalizeStub,
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
