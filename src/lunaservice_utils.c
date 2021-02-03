/* @@@LICENSE
*
*      Copyright (c) 2021 LG Electronics, Inc.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* LICENSE@@@ */


/**
 * @file lunaservice_utils.c
 *
 * @brief Convenience functions for sending luna error messages
 *
 */

#include "lunaservice_utils.h"

luna_service_request_t* luna_service_request_new(LSHandle *handle, LSMessage *message)
{
	luna_service_request_t *req = NULL;

	req = g_new0(luna_service_request_t, 1);
	req->handle = handle;
	req->message = message;

	return req;
}

void
LSMessageReplyErrorUnknown(LSHandle *sh, LSMessage *message)
{
	LSError lserror;
	LSErrorInit(&lserror);

	bool retVal = LSMessageReply(sh, message, "{\"returnValue\":false,"
	"\"errorText\":\"Unknown Error.\"}", &lserror);
	if (!retVal)
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}
}

void
LSMessageReplyErrorInvalidParams(LSHandle *sh, LSMessage *message)
{
	LSError lserror;
	LSErrorInit(&lserror);

	bool retVal = LSMessageReply(sh, message, "{\"returnValue\":false,"
	"\"errorText\":\"Invalid parameters.\"}", NULL);
	if (!retVal)
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}
}

void
LSMessageReplyErrorBadJSON(LSHandle *sh, LSMessage *message)
{
	LSError lserror;
	LSErrorInit(&lserror);

	bool retVal = LSMessageReply(sh, message, "{\"returnValue\":false,"
	"\"errorText\":\"Malformed json.\"}", NULL);
	if (!retVal)
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}
}

void
LSMessageReplyCustomError(LSHandle *sh, LSMessage *message, const char *errormsg)
{
	LSError lserror;
	LSErrorInit(&lserror);
	char *errorString;

	errorString = g_strdup_printf("{\"returnValue\":false,\"errorText\":\"%s\"}", errormsg);

	bool retVal = LSMessageReply(sh, message, errorString, NULL);
	if (!retVal)
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	g_free(errorString);
}

void
LSMessageReplySuccess(LSHandle *sh, LSMessage *message)
{
	LSError lserror;
	LSErrorInit(&lserror);

	bool retVal = LSMessageReply(sh, message, "{\"returnValue\":true}",
	NULL);
	if (!retVal)
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}
}

bool LSMessageValidateSchema(LSHandle *sh, LSMessage *message, raw_buffer schema, jvalue_ref *parsedObj)
{
	bool ret = false;
	jschema_ref input_schema = jschema_parse (schema, DOMOPT_NOOPT, NULL);
	if(!input_schema)
		return false;

	JSchemaInfo schemaInfo;
	jschema_info_init(&schemaInfo, input_schema, NULL, NULL);
	*parsedObj = jdom_parse(j_cstr_to_buffer(LSMessageGetPayload(message)), DOMOPT_NOOPT, &schemaInfo);

	if (jis_null(*parsedObj))
	{
		input_schema = jschema_parse (j_cstr_to_buffer(SCHEMA_ANY), DOMOPT_NOOPT, NULL);
		jschema_info_init(&schemaInfo, input_schema, NULL, NULL);
		*parsedObj = jdom_parse(j_cstr_to_buffer(LSMessageGetPayload(message)), DOMOPT_NOOPT, &schemaInfo);

		if(jis_null(*parsedObj))
		{
			LSMessageReplyErrorBadJSON(sh, message);
		}
		else
		{
			LSMessageReplyCustomError(sh, message, "Could not validate json message against schema");
			j_release(parsedObj);
		}
	}
	else
		ret = true;

	jschema_release(&input_schema);
	return ret;
}
