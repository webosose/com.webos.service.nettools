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
 * @file  nettools_service.c
 *
 * @brief Implements all of the com.webos.service.nettools methods
 *
 */

//->Start of API documentation comment block
/**
@page com_webos_nettools com.webos.nettools

@brief Provides a selection of standard network tools

Each call has a standard return in the case of a failure, as follows:

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | False to indicate an error
errorCode | Yes | Integer | Error code
errorText | Yes | String | Error description

@{
@}
*/
//->End of API documentation comment block


#include <glib.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <pbnjson.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <glib-object.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "nettools_service.h"
#include "lunaservice_utils.h"
#include "json_utils.h"

static LSHandle *pLsHandle;

bool is_valid_ipaddress(const char *ipAddress)
{
	struct sockaddr_in sa;
	int result;
	if (ipAddress == NULL)
	{
		return false;
	}
	result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
	return result != 0;
}

bool is_safe_hostname(const char *url)
{
	const char *p;
	if (url == NULL)
		return false;

	if (!g_str_has_prefix(url, "www."))
		return false;

	if (!(g_str_has_suffix(url, ".org") || g_str_has_suffix(url, ".com") ||
			g_str_has_suffix(url, ".net") || g_str_has_suffix(url, ".gov") ||
			g_str_has_suffix(url, ".edu") || g_str_has_suffix(url, ".jp") ||
			g_str_has_suffix(url, ".int") || g_str_has_suffix(url, ".mil")))
		return false;

	if(is_valid_ipaddress(url))
		return true;

	for (p = url; *p; p++ )
	{
		if (!(isalnum(*p) || *p == '.' || *p == '-'))
			return false;
	}
	return true;
}

/**
 * Execute "ping" shell command
 *
 * @param[IN] hostname Hostname to be pinged
 * @param[IN] ifname Interface name used for pinging
 * @param[IN] sh LS2 handle
 * @param[IN] message LS2 message
 *
 */
static void ping(const char *hostname, const char *ifname, int packetSize, LSHandle *sh, LSMessage *message)
{
	gchar *pingcmd = NULL, *ifnameStr = NULL, *pktSizeStr = NULL;
	gchar *pingStdout = NULL, *pingStderr = NULL, **lines = NULL;
	int exitStatus = 0, i = 0, len = 0;
	unsigned char ipaddress[16] = {0,};
	char domainName[256] = {0,};

	if(NULL == hostname)
	{
		LSMessageReplyErrorUnknown(sh, message);
		goto exit;
	}

	if(NULL != ifname)
		ifnameStr = g_strdup_printf(" -I %s", ifname);

	if((packetSize > 0) && (packetSize <= 65000))
		pktSizeStr = g_strdup_printf(" -s %d", packetSize);

	if(pktSizeStr && ifnameStr)
		pingcmd = g_strconcat("ping -c 1 -w 3 ", hostname, pktSizeStr, ifnameStr, NULL);
	else if(pktSizeStr)
		pingcmd = g_strconcat("ping -c 1 -w 3 ", hostname, pktSizeStr, NULL);
	else if(ifnameStr)
		pingcmd = g_strconcat("ping -c 1 -w 3 ", hostname, ifnameStr, NULL);
	else
		pingcmd = g_strconcat("ping -c 1 -w 3 ", hostname, NULL);

	if((pingcmd == NULL) || !g_spawn_command_line_sync(pingcmd, &pingStdout, &pingStderr, &exitStatus, NULL))
	{
		LSMessageReplyErrorUnknown(sh, message);
		goto exit;
	}

	if(exitStatus == 0)
	{
		lines = g_strsplit(pingStdout, "\n", 0);

		for (i = 0, len = g_strv_length(lines); i < len; i++)
		{
			if(g_strstr_len(lines[i], -1, "bytes of data.") != NULL)
			{
				g_strdelimit(lines[i], "()", ' ');

				if(sscanf(lines[i], "PING %255s  %15s ", domainName, ipaddress) != EOF)
				{
					if(domainName[0] == 0 || ipaddress[0] == 0)
					{
						LSMessageReplyCustomError(sh, message, "Parsing Error");
						goto exit;
					}
				}
			}

			if(g_strstr_len(lines[i], -1, "bytes from") != NULL)
			{
				char time[6] = {0,};
				long pkts_ttl = 0, pkts_byte = 0, pkts_seq = 0;
				char reqName[256] = {0,}, ipaddr[16] = {0,};

				if(g_strrstr(lines[i], "):") != NULL)
				{
					g_strdelimit(lines[i], ":=()", ' ');

					if(sscanf(lines[i], "%ld bytes from %255s  %15s   icmp_seq %ld ttl %ld time %5s ms", &pkts_byte, reqName, ipaddr, &pkts_seq, &pkts_ttl , time) != EOF)
					{
						if(pkts_byte > 0)
						{
							LSError lserror;
							LSErrorInit(&lserror);
							char *replyString;

							replyString = g_strdup_printf("{\"returnValue\":true,\"ipAddress\":\"%s\", \"hostname\":\"%s\", \"bytes\":%ld, \"ttl\":%ld, \"time\":%3.3f}",
								ipaddress, domainName, pkts_byte, pkts_ttl, atof(time));

							bool retVal = LSMessageReply(sh, message, replyString, NULL);

							if (!retVal)
							{
								LSErrorPrint(&lserror, stderr);
								LSErrorFree(&lserror);
							}

							g_free(replyString);
						}
						else
						{
							LSMessageReplyCustomError(sh, message, "Poor network");
						}
					}
				}
				else
				{
					g_strdelimit(lines[i], ":=", ' ');

					if(sscanf(lines[i], "%ld bytes from %15s  icmp_seq %ld ttl %ld time %5s ms", &pkts_byte, ipaddr, &pkts_seq, &pkts_ttl , time) != EOF)
					{
						if(pkts_byte > 0)
						{
							LSError lserror;
							LSErrorInit(&lserror);
							char *replyString;

							replyString = g_strdup_printf("{\"returnValue\":true,\"ipaddress\":\"%s\", \"hostname\":\"%s\", \"bytes\":%ld, \"ttl\":%ld, \"time\":%3.3f}",
								ipaddress, domainName, pkts_byte, pkts_ttl, atof(time));

							bool retVal = LSMessageReply(sh, message, replyString, NULL);

							if (!retVal)
							{
								LSErrorPrint(&lserror, stderr);
								LSErrorFree(&lserror);
							}

							g_free(replyString);
						}
						else
						{
							LSMessageReplyCustomError(sh, message, "Poor network");
						}
					}
				}
			}
		}
	}
	else
	{
		lines = g_strsplit(pingStderr, "\n", 0);
		for (i = 0, len = g_strv_length(lines); i < len; i++)
		{
			if(g_strstr_len(lines[i], -1, "unknown host") != NULL)
			{
				LSMessageReplyCustomError(sh, message, "Unknown host");
				goto exit;
			}
		}
		LSMessageReplyCustomError(sh, message, "Request timed out");
	}

exit:
	g_strfreev(lines);
	g_free(ifnameStr);
	g_free(pktSizeStr);
	g_free(pingcmd);
}


/**
 *  @brief Handler for "ping" command.
 *
 *  JSON format:
 *  luna://com.webos.service.nettools/ping {"hostname":<Hostname to be pinged>}
 *  luna://com.webos.service.nettools/ping {"hostname":<Hostname to be pinged>,"ifName":<Interface used for pinging>}
 *
 */

static bool handlePingCommand(LSHandle *sh, LSMessage *message, void* context)
{
	// Add any validation checks here
	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if(!LSMessageValidateSchema(sh, message,
								j_cstr_to_buffer(STRICT_SCHEMA(PROPS_3(PROP(hostname, string), PROP(ifName, string), PROP(packetsize, integer))
										REQUIRED_1(hostname))), &parsedObj))
		{
			return true;
		}

	jvalue_ref reply = jobject_create();
	jvalue_ref hostnameObj = {0}, ifNameObj = {0}, packetsizeObj = {0};
	char *hostname = NULL, *ifName = NULL;
	int packetSize = 0;

	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("hostname"), &hostnameObj))
	{
		raw_buffer hostname_buf = jstring_get(hostnameObj);
		hostname = g_strdup(hostname_buf.m_str);
		jstring_free_buffer(hostname_buf);
	}

	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("ifName"), &ifNameObj))
	{
		raw_buffer ifName_buf = jstring_get(ifNameObj);
		ifName = g_strdup(ifName_buf.m_str);
		jstring_free_buffer(ifName_buf);
	}

	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("packetsize"), &packetsizeObj))
	{
		jnumber_get_i32(packetsizeObj, &packetSize);
	}

	ping(hostname, ifName, packetSize, sh, message);

	g_free(hostname);
	g_free(ifName);
	j_release(&parsedObj);
	j_release(&reply);

	return true;
}


static void pingV6(const char *hostname, const char *ifname, int packetSize, LSHandle *sh, LSMessage *message)
{
	gchar *pingcmd = NULL, *ifnameStr = NULL, *pktSizeStr = NULL;
	gchar *pingStdout = NULL, *pingStderr = NULL, **lines = NULL;
	int exitStatus = 0, i = 0, len = 0;
	unsigned char ipaddress[40] = {0,};
	char domainName[256] = {0,};

	if(NULL == hostname)
	{
		LSMessageReplyErrorUnknown(sh, message);
		goto exit;
	}

	if(NULL != ifname)
		ifnameStr = g_strdup_printf(" -I %s", ifname);

	if((packetSize > 0) && (packetSize <= 65000))
		pktSizeStr = g_strdup_printf(" -s %d", packetSize);

	if(pktSizeStr && ifnameStr)
		pingcmd = g_strconcat("ping6 -c 1 -w 3 ", hostname, pktSizeStr, ifnameStr, NULL);
	else if(pktSizeStr)
		pingcmd = g_strconcat("ping6 -c 1 -w 3 ", hostname, pktSizeStr, NULL);
	else if(ifnameStr)
		pingcmd = g_strconcat("ping6 -c 1 -w 3 ", hostname, ifnameStr, NULL);
	else
		pingcmd = g_strconcat("ping6 -c 1 -w 3 ", hostname, NULL);

	if((pingcmd == NULL) || !g_spawn_command_line_sync(pingcmd, &pingStdout, &pingStderr, &exitStatus, NULL))
	{
		LSMessageReplyErrorUnknown(sh, message);
		goto exit;
	}

	if(exitStatus == 0)
	{
		lines = g_strsplit(pingStdout, "\n", 0);

		for (i = 0, len = g_strv_length(lines); i < len; i++)
		{
			if(g_strstr_len(lines[i], -1, "data bytes") != NULL)
			{
				g_strdelimit(lines[i], "()", ' ');

				if(sscanf(lines[i], "PING %255s  %39s ", domainName, ipaddress) != EOF)
				{
					if(domainName[0] == 0 || ipaddress[0] == 0)
					{
						LSMessageReplyCustomError(sh, message, "Parsing Error");
						goto exit;
					}
				}
			}

			if(g_strstr_len(lines[i], -1, "bytes from") != NULL)
			{
				char time[6] = {0,};
				long pkts_ttl = 0, pkts_byte = 0, pkts_seq = 0;
				char reqName[256] = {0,}, ipaddr[40] = {0,};

				if(g_strrstr(lines[i], ")") != NULL)
				{
					g_strdelimit(lines[i], "=()", ' ');

					if(sscanf(lines[i], "%ld bytes from %255s  %39s  seq %ld ttl %ld time %5s ms", &pkts_byte, reqName, ipaddr, &pkts_seq, &pkts_ttl , time) != EOF)
					{
						if(pkts_byte > 0)
						{
							LSError lserror;
							LSErrorInit(&lserror);
							char *replyString;

							replyString = g_strdup_printf("{\"returnValue\":true,\"ipAddress\":\"%s\", \"hostname\":\"%s\", \"bytes\":%ld, \"ttl\":%ld, \"time\":%3.3f}",
								ipaddress, domainName, pkts_byte, pkts_ttl, atof(time));

							bool retVal = LSMessageReply(sh, message, replyString, NULL);

							if (!retVal)
							{
								LSErrorPrint(&lserror, stderr);
								LSErrorFree(&lserror);
							}
							g_free(replyString);
						}
						else
						{
							LSMessageReplyCustomError(sh, message, "Poor network");
						}
					}
				}
				else
				{
					g_strdelimit(lines[i], "=", ' ');

					if(sscanf(lines[i], "%ld bytes from %39s seq %ld ttl %ld time %5s ms", &pkts_byte, ipaddr, &pkts_seq, &pkts_ttl , time) != EOF)
					{
						if(pkts_byte > 0)
						{
							LSError lserror;
							LSErrorInit(&lserror);
							char *replyString;

							replyString = g_strdup_printf("{\"returnValue\":true,\"ipaddress\":\"%s\", \"hostname\":\"%s\", \"bytes\":%ld, \"ttl\":%ld, \"time\":%3.3f}",
								ipaddress, domainName, pkts_byte, pkts_ttl, atof(time));

							bool retVal = LSMessageReply(sh, message, replyString, NULL);

							if (!retVal)
							{
								LSErrorPrint(&lserror, stderr);
								LSErrorFree(&lserror);
							}

							g_free(replyString);
						}
						else
						{
							LSMessageReplyCustomError(sh, message, "Poor network");
						}
					}
				}
			}
		}
	}
	else
	{
		lines = g_strsplit(pingStderr, "\n", 0);
		for (i = 0, len = g_strv_length(lines); i < len; i++)
		{
			if(g_strstr_len(lines[i], -1, "unknown host") != NULL)
			{
				LSMessageReplyCustomError(sh, message, "Unknown host");
				goto exit;
			}
		}
		LSMessageReplyCustomError(sh, message, "Request timed out");
	}

exit:
	g_strfreev(lines);
	g_free(ifnameStr);
	g_free(pktSizeStr);
	g_free(pingcmd);
}


/**
 *  @brief Handler for "ping6" command.
 *
 *  JSON format:
 *  luna://com.webos.service.nettools/ping6 {"hostname":<Hostname to be pinged>}
 *  luna://com.webos.service.nettools/ping6 {"hostname":<Hostname to be pinged>,"ifName":<Interface used for pinging>}
 *
 */

static bool handlePingV6Command(LSHandle *sh, LSMessage *message, void* context)
{
	// Add any validation checks here
	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if(!LSMessageValidateSchema(sh, message,
								j_cstr_to_buffer(STRICT_SCHEMA(PROPS_3(PROP(hostname, string), PROP(ifName, string), PROP(packetsize, integer))
										REQUIRED_1(hostname))), &parsedObj))
		{
			return true;
		}

	jvalue_ref reply = jobject_create();
	jvalue_ref hostnameObj = {0}, ifNameObj = {0}, packetsizeObj = {0};
	char *hostname = NULL, *ifName = NULL;
	int packetSize = 0;

	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("hostname"), &hostnameObj))
	{
		raw_buffer hostname_buf = jstring_get(hostnameObj);
		hostname = g_strdup(hostname_buf.m_str);
		jstring_free_buffer(hostname_buf);
	}

	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("ifName"), &ifNameObj))
	{
		raw_buffer ifName_buf = jstring_get(ifNameObj);
		ifName = g_strdup(ifName_buf.m_str);
		jstring_free_buffer(ifName_buf);
	}

	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("packetsize"), &packetsizeObj))
	{
		jnumber_get_i32(packetsizeObj, &packetSize);
	}

	pingV6(hostname, ifName, packetSize, sh, message);

	g_free(hostname);
	g_free(ifName);
	j_release(&parsedObj);
	j_release(&reply);

	return true;
}


/**
 * Execute "arping" shell command
 *
 * @param[IN] ipaddress IP address whose mac address needs to be resolved
 * @param[IN] ifname Interface name used for arping
 * @param[IN] sh LS2 handle
 * @param[IN] message LS2 message
 *
 */

static void arping(const char *ipaddress, const char *ifname, LSHandle *sh, LSMessage *message)
{
	gchar *arpingcmd = NULL, **lines = NULL;
	gchar *arpingStdout = NULL, *arpingStderr = NULL;
	int exitStatus = 0, i = 0, len = 0;

	if(NULL == ipaddress || NULL == ifname)
	{
		LSMessageReplyErrorUnknown(sh, message);
		goto exit;
	}

	arpingcmd = g_strconcat("arping  -c 1 -f -I ", ifname, " ", ipaddress, NULL);

	if((arpingcmd == NULL) || !g_spawn_command_line_sync(arpingcmd, &arpingStdout, &arpingStderr, &exitStatus, NULL))
	{
		LSMessageReplyErrorUnknown(sh, message);
		goto exit;
	}

	if(exitStatus == 0)
	{
		lines = g_strsplit(arpingStdout, "\n", 0);
		for (i = 0, len = g_strv_length(lines); i < len; i++)
		{
			if(g_strstr_len(lines[i], -1, "reply from") != NULL)
			{
				gchar tmpstr1[32], tmpstr2[32], tmpstr3[32], macaddress[32];
				if(sscanf(lines[i], "%31s reply from %31s [%31s] %31s", tmpstr1, tmpstr2, macaddress, tmpstr3) != EOF)
				{
					macaddress[strlen(macaddress)-1] = 0;
					jvalue_ref reply = jobject_create();
					LSError lserror;
					LSErrorInit(&lserror);

					jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
					jobject_put(reply, J_CSTR_TO_JVAL("foundMacAddress"), jstring_create(macaddress));
					jschema_ref response_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
					if(!response_schema)
					{
						LSMessageReplyErrorUnknown(sh, message);
						goto cleanup;
					}
					if (!LSMessageReply(sh, message, jvalue_tostring(reply, response_schema), &lserror))
					{
						LSErrorPrint(&lserror, stderr);
						LSErrorFree(&lserror);
					}
					jschema_release(&response_schema);
cleanup:
					if (LSErrorIsSet(&lserror))
					{
						LSErrorPrint(&lserror, stderr);
						LSErrorFree(&lserror);
					}
					j_release(&reply);
				}
			}
		}
	}
	else
	{
		lines = g_strsplit(arpingStderr, "\n", 0);
		for (i = 0, len = g_strv_length(lines); i < len; i++)
		{
			if(g_strstr_len(lines[i], -1, "Network is unreachable") != NULL)
			{
				LSMessageReplyCustomError(sh, message, "arping failed: unreachable network");
				goto exit;
			}
		}
		LSMessageReplyCustomError(sh, message, "arping failed: mac address not found");
	}

exit:
	g_strfreev(lines);
	g_free(arpingcmd);
}

//->Start of API documentation comment block
/**
@page com_webos_nettools com.webos.nettools
@{
@section com_webos_nettools_arping arping

Performs an ARP request to resolve IP address to mac address which can
then be used to detect IP address conflicts.

@par Parameters
Name | Required | Type | Description
-----|--------|------|----------
ifName | yes | String | Interface to use for the arping command
ipAddress | yes | String | ipAddress to ping

@par Returns(Call)
Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True
foundMacAddress | No | String | Any MAC address found for the IP address

@par Returns(Subscription)
None

@}
*/
//->End of API documentation comment block

/**
 *  @brief Handler for "arping" command.
 *
 *  JSON format:
 *  luna://com.webos.service.nettools/arping {"ipAddress":<target IP address>,"ifName":<Interface used for arping>}
 */

static bool handleArpingCommand(LSHandle *sh, LSMessage *message, void* context)
{
	// Add any validation checks here
	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if(!LSMessageValidateSchema(sh, message, j_cstr_to_buffer(STRICT_SCHEMA(PROPS_2(PROP(ipAddress, string), PROP(ifName, string))
			REQUIRED_2(ipAddress, ifName))), &parsedObj))
		return true;

	jvalue_ref reply = jobject_create();
	jvalue_ref ipAddressObj = {0}, ifNameObj = {0};
	char *ipAddress = NULL, *ifName = NULL;

	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("ipAddress"), &ipAddressObj))
	{
		raw_buffer ipAddress_buf = jstring_get(ipAddressObj);
		ipAddress = g_strdup(ipAddress_buf.m_str);
		jstring_free_buffer(ipAddress_buf);
		if(!is_valid_ipaddress(ipAddress))
		{
			LSMessageReplyErrorInvalidParams(sh, message);
			goto cleanup;
		}
	}

	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("ifName"), &ifNameObj))
	{
		raw_buffer ifName_buf = jstring_get(ifNameObj);
		ifName = g_strdup(ifName_buf.m_str);
		jstring_free_buffer(ifName_buf);
	}

	arping(ipAddress, ifName, sh, message);

cleanup:
	g_free(ipAddress);
	g_free(ifName);
	j_release(&parsedObj);
	j_release(&reply);

	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_nettools com.webos.nettools
@{
@section com_webos_nettools_resolvehostname resolvehostname

Performs a DNS request to resolve hostname to list of all IP addresses that it maps to.

@par Parameters
Name | Required | Type | Description
-----|--------|------|----------
hostname | yes | String | Hostname to be resolved

@par Returns(Call)
Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True
resolvedIpAddress | no | Array of String | List of resolved IP addresses

@par Returns(Subscription)
None

@}
*/
//->End of API documentation comment block

/**
 *  @brief Handler for "resolvehostname" command.
 *
 *  JSON format:
 *  luna://com.webos.service.nettools/resolvehostname {"hostname":<Hostname for resolving ip address>}
 *
 */

static bool handleResolveHostnameCommand(LSHandle *sh, LSMessage *message, void* context)
{
	// Add any validation checks here
	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if(!LSMessageValidateSchema(sh, message, j_cstr_to_buffer(STRICT_SCHEMA(PROPS_1(PROP(hostname, string))
			REQUIRED_1(hostname))), &parsedObj))
		return true;

	jvalue_ref reply = jobject_create();
	jvalue_ref hostnameObj = {0};
	char *hostname = NULL, ip_str[INET6_ADDRSTRLEN];
	struct addrinfo hints, *res = NULL, *res_tmp;
	int status;
	void *addr;
	LSError lserror;
	LSErrorInit (&lserror);

	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("hostname"), &hostnameObj))
	{
		raw_buffer hostname_buf = jstring_get(hostnameObj);
		hostname = g_strdup(hostname_buf.m_str);
		jstring_free_buffer(hostname_buf);
		if(!is_safe_hostname(hostname))
		{
			LSMessageReplyCustomError(sh, message, "Invalid hostname");
			goto cleanup;
		}
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	status = getaddrinfo(hostname, NULL, &hints, &res);
	if (status || res  == NULL) {
		LSMessageReplyCustomError(sh, message, "Error in resolving hostname");
		goto cleanup;
	}
	else {
		jvalue_ref ipAddressList = jarray_create(NULL);

		for(res_tmp = res; res_tmp != NULL; res_tmp = res_tmp->ai_next)
		{
			if(res_tmp->ai_family == AF_INET) {
				addr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
			}
			else {
				addr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
			}

			inet_ntop(res_tmp->ai_family, addr, ip_str, sizeof(ip_str));
			jarray_append(ipAddressList, jstring_create((gchar *)ip_str));
		}

		jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
		jobject_put(reply, J_CSTR_TO_JVAL("resolvedIpAddresses"), ipAddressList);
		jschema_ref response_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
		if(!response_schema)
		{
			LSMessageReplyErrorUnknown(sh, message);
			goto cleanup;
		}
		if (!LSMessageReply(sh, message, jvalue_tostring(reply, response_schema), &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}
		jschema_release(&response_schema);
	}
cleanup:
	g_free(hostname);
	if(res != NULL)
	{
		freeaddrinfo(res);
	}
	if (LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}
	j_release(&parsedObj);
	j_release(&reply);

	return true;
}

/**
 * Test if socket connection to desired host is successful
 *
 * @param hostUrl hostUrl used as socket dest address
 *
 * @return TRUE if successful, FALSE if socket creation/connection failed
 */

static gboolean testHttpSocket(const char *hostUrl)
{
	struct addrinfo hints, *res = NULL, *res_tmp;
	int httpSocket;
	int rc, flags = 0;
	fd_set rset, wset;
	struct timeval tval;
	gboolean ret = FALSE;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	rc = getaddrinfo(hostUrl, "http", &hints, &res);
	if (rc || res == NULL)
	{
		return FALSE;
	}

	for(res_tmp = res; res_tmp != NULL && ret == FALSE; res_tmp = res_tmp->ai_next)
	{
		flags = 0;
		httpSocket = socket(res_tmp->ai_family, res_tmp->ai_socktype, res_tmp->ai_protocol);
		if(httpSocket < 0)
		{
			continue;
		}

		flags = fcntl(httpSocket, F_GETFL, 0);
		fcntl(httpSocket, F_SETFL, flags | O_NONBLOCK);

		do
		{
			rc = connect(httpSocket, res_tmp->ai_addr, res_tmp->ai_addrlen);
			if (rc < 0 && errno != EINPROGRESS)
			{
				break;
			}
			if (rc == 0)
			{
				ret = TRUE;
				break;
			}

			FD_ZERO(&rset);
			FD_SET(httpSocket, &rset);
			wset = rset;
			tval.tv_sec = 5;
			tval.tv_usec = 0;

			rc = select(httpSocket+1, &rset, &wset, NULL, &tval);
			if(rc == 0)
			{
				break;
			}
			if(FD_ISSET(httpSocket, &rset) || FD_ISSET(httpSocket, &wset))
			{
				int error;
				socklen_t len;
				len = sizeof(error);
				if(getsockopt(httpSocket, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
				{
					break;
				}
			}
			ret = TRUE;
		} while(0);

		if(httpSocket >= 0)
		{
			if(flags)
			{
				fcntl(httpSocket, F_SETFL, flags);
			}
			close(httpSocket);
		}
	}

	freeaddrinfo(res);
	return ret;
}

//->Start of API documentation comment block
/**
@page com_webos_nettools com.webos.nettools
@{
@section com_webos_nettools_checkhttp checkhttp

Create a TCP socket and test connection to the given host URL.

@par Parameters
Name | Required | Type | Description
-----|--------|------|----------
hostUrl | yes | String | URL to test

@par Returns(Call)
Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True on success

@par Returns(Subscription)
None

@}
*/
//->End of API documentation comment block

/**
 *  @brief Handler for "checkhttp" command.
 *
 *  JSON format:
 *  luna://com.webos.service.nettools/checkhttp {"hostUrl":<hostUrl for checking http connection>}
 *
 */

static bool handleCheckHttpCommand(LSHandle *sh, LSMessage *message, void* context)
{
	// Add any validation checks here
	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if(!LSMessageValidateSchema(sh, message, j_cstr_to_buffer(STRICT_SCHEMA(PROPS_1(PROP(hostUrl, string))
			REQUIRED_1(hostUrl))), &parsedObj))
		return true;

	jvalue_ref reply = jobject_create();
	jvalue_ref hostUrlObj = {0};
	char *hostUrl = NULL;
	LSError lserror;
	LSErrorInit (&lserror);

	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("hostUrl"), &hostUrlObj))
	{
		raw_buffer hostUrl_buf = jstring_get(hostUrlObj);
		hostUrl = g_strdup(hostUrl_buf.m_str);
		jstring_free_buffer(hostUrl_buf);
		if(!is_safe_hostname(hostUrl))
		{
			LSMessageReplyCustomError(sh, message, "Invalid hostUrl");
			goto cleanup;
		}
	}

	if(testHttpSocket(hostUrl) == TRUE)
	{
		LSMessageReplySuccess(sh, message);
	}
	else
	{
		LSMessageReplyCustomError(sh, message, "Error in http connection");
	}

cleanup:
	g_free(hostUrl);
	j_release(&parsedObj);
	j_release(&reply);

	return true;
}


//->Start of API documentation comment block
/**
@page com_webos_nettools com.webos.nettools
@{
@section com_webos_nettools_gethostname gethostname

Get the hostname for the system

@par Parameters
Name | Required | Type | Description
-----|--------|------|----------
subscribe | No | Boolean | true to subscribe to this method

@par Returns(Call)
Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True on success
hostname | yes | String | Hostname for the system

@par Returns(Subscription)

As for a successful call
@}
*/
//->End of API documentation comment block


/**
 *  @brief Handler for "gethostname" command.
 *
 *  JSON format:
 *  luna://com.webos.service.nettools/gethostname {}
 *
 */

static bool handleGetHostNameCommand(LSHandle *sh, LSMessage *message, void* context)
{
	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if(!LSMessageValidateSchema(sh, message, j_cstr_to_buffer(SCHEMA_1(PROP(subscribe, boolean))), &parsedObj))
		return true;

	jvalue_ref reply = jobject_create();
	LSError lserror;
	LSErrorInit (&lserror);
	bool subscribed = false;

	if (LSMessageIsSubscription(message))
	{
		if (!LSSubscriptionProcess(sh, message, &subscribed, &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}
		jobject_put(reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(subscribed));
	}

	jschema_ref response_schema = NULL;
	char hostname[256];

	int err = gethostname(hostname, sizeof(hostname));
	if(err)
	{
		LSMessageReplyCustomError(sh, message, "Error in calling gethostname");
		goto cleanup;
	}

	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	jobject_put(reply, J_CSTR_TO_JVAL("hostname"), jstring_create(hostname));
	response_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
	if(!response_schema)
	{
		LSMessageReplyErrorUnknown(sh, message);
		goto cleanup;
	}
	if (!LSMessageReply(sh, message, jvalue_tostring(reply, response_schema), &lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}
	jschema_release(&response_schema);

cleanup:
	if (LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}
	j_release(&parsedObj);
	j_release(&reply);

	return true;
}

static void send_hostname_to_subscribers(const gchar *hostname)
{
	jvalue_ref reply = jobject_create();
	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	jobject_put(reply, J_CSTR_TO_JVAL("hostname"), jstring_create(hostname));

	jschema_ref response_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
	if(response_schema)
	{
		const char *payload = jvalue_tostring(reply, response_schema);
		LSError lserror;
		LSErrorInit(&lserror);
		if (!LSSubscriptionReply(pLsHandle, "/gethostname", payload, &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}
		jschema_release(&response_schema);
	}
	j_release(&reply);
}


//->Start of API documentation comment block
/**
@page com_webos_nettools com.webos.nettools
@{
@section com_webos_nettools_sethostname sethostname

Set a new hostname for the system

@par Parameters
Name | Required | Type | Description
-----|--------|------|----------
hostname | yes | String | New hostname for the system

@par Returns(Call)
Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True on success

@par Returns(Subscription)
None

@}
*/
//->End of API documentation comment block


/**
 *  @brief Handler for "sethostname" command.
 *
 *  JSON format:
 *  luna://com.webos.service.nettools/sethostname {"hostname":<New hostname>}
 *
 */

static bool handleSetHostNameCommand(LSHandle *sh, LSMessage *message, void* context)
{
	// Add any validation checks here

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if(!LSMessageValidateSchema(sh, message, j_cstr_to_buffer(STRICT_SCHEMA(PROPS_1(PROP(hostname, string))
			REQUIRED_1(hostname))), &parsedObj))
		return true;

	jvalue_ref hostnameObj;
	char *hostname = NULL, *hostnameTmp = NULL;
	int err = 0;

	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("hostname"), &hostnameObj))
	{
		raw_buffer hostname_buf = jstring_get(hostnameObj);
		hostname = g_strdup(hostname_buf.m_str);
		jstring_free_buffer(hostname_buf);
	}

        if(hostname == NULL)
        {
                g_critical("Out of Memory!!!");
                abort();
        }

	// Append newline character to hostname
	hostnameTmp = g_new0(gchar, strlen(hostname)+1);
	if(hostnameTmp == NULL)
	{
		g_critical("Out of Memory!!!");
		abort();
	}
	g_strlcpy(hostnameTmp, hostname, strlen(hostname)+1);
	hostnameTmp[strlen(hostname)]='\n';

	gboolean ret = g_file_set_contents(HOSTNAME_FILE_DIR "/hostname", hostnameTmp, -1, NULL);
	if(!ret)
	{
		LSMessageReplyCustomError(sh, message, "Error in setting " HOSTNAME_FILE_DIR "/hostname");
		goto cleanup;
	}

	err = sethostname(hostname, strlen(hostname));
	if(err)
	{
		LSMessageReplyCustomError(sh, message, "Error in calling sethostname");
		goto cleanup;
	}

	LSMessageReplySuccess(sh, message);
	send_hostname_to_subscribers(hostname);

cleanup:
	g_free(hostname);
	g_free(hostnameTmp);
	j_release(&parsedObj);

	return true;
}


/**
 * com.webos.service.nettools service Luna Method Table
 */

static LSMethod nettools_methods[] = {
    { LUNA_METHOD_PING,                 handlePingCommand },
    { LUNA_METHOD_PINGV6,             handlePingV6Command },
    { LUNA_METHOD_ARPING,               handleArpingCommand },
    { LUNA_METHOD_RESOLVEHOSTNAME,      handleResolveHostnameCommand },
    { LUNA_METHOD_CHECKHTTP,            handleCheckHttpCommand },
    { LUNA_METHOD_GETHOSTNAME,          handleGetHostNameCommand },
    { LUNA_METHOD_SETHOSTNAME,          handleSetHostNameCommand },
    { NULL,  }
};

/**
 *  @brief Initialize com.webos.service.nettools service and all of its methods
 */

int initialize_nettools_ls2_calls( GMainLoop *mainloop )
{
	LSError lserror;
	LSErrorInit (&lserror);
	pLsHandle       = NULL;

	if(NULL == mainloop)
		goto Exit;

	if (LSRegister(NETTOOLS_LUNA_SERVICE_NAME, &pLsHandle, &lserror) == false)
	{
		g_error("LSRegister() returned error");
		goto Exit;
	}

	if (LSRegisterCategory(pLsHandle, NULL, nettools_methods, NULL, NULL, &lserror) == false)
	{
		g_error("LSRegisterCategory() returned error");
		goto Exit;
	}

	if (LSGmainAttach(pLsHandle, mainloop, &lserror) == false)
	{
		g_error("LSGmainAttach() returned error");
		goto Exit;
	}

	return 0;

Exit:
	if (LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	if (pLsHandle)
	{
		LSErrorInit (&lserror);
		if(LSUnregister(pLsHandle, &lserror) == false)
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}
	}

	return -1;
}
