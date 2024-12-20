/* @@@LICENSE
*
*      Copyright (c) 2024 LG Electronics, Inc.
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
#include <ifaddrs.h>

#include "nettools_service.h"
#include "lunaservice_utils.h"
#include "json_utils.h"
#include "errors.h"

#define CONFIG_FILE "/etc/nettools_access_control.conf"

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
	int exitStatus = 0;
	unsigned int i = 0, len = 0;
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
	int exitStatus = 0;
	unsigned int i = 0, len = 0;
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
	int exitStatus = 0;
	unsigned int i = 0, len = 0;

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
		if (flags == -1)
		{
			close(httpSocket);
			continue;
		}

		int result = fcntl(httpSocket, F_SETFL, flags | O_NONBLOCK);
		if (result == -1)
		{
			close(httpSocket);
			continue;
		}

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
				int fcntl_res = fcntl(httpSocket, F_SETFL, flags);
				if (fcntl_res == -1)
				{
					g_error("fcntl F_SETFL on httpSocket failed");
				}
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
// Function to read the entire file into a string
char* read_file(const char *filename) {
        GError *error = NULL;
        gchar *content;
        gsize length;

        if (!g_file_get_contents(filename, &content, &length, &error)) {
                g_printerr("Could not open config file: %s\n", error->message);
                g_error_free(error);
                return NULL;
        }
        return content;
}

// Function to check if an app is authorized
int is_app_authorized(const char *app_name) {
        char *config_data = read_file(CONFIG_FILE);
        if (config_data == NULL) {
            return 0;
        }

        jvalue_ref parsedObj = {0};
        JSchemaInfo schemaInfo;
        jschema_info_init(&schemaInfo, jschema_all(), NULL, NULL);

        parsedObj = jdom_parse(j_cstr_to_buffer(config_data), DOMOPT_NOOPT, &schemaInfo);

        if (jis_null(parsedObj)) {
                g_printerr("Unable to parse JSON\n");
                j_release(&parsedObj);
                g_free(config_data);
                return 0;
        }

        jvalue_ref whitelistObj, blacklistObj;
        int authorized = 0;

        if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("blacklist"), &blacklistObj) && jis_array(blacklistObj)) {
                for (ssize_t i = 0; i < jarray_size(blacklistObj); i++) {
                        jvalue_ref entry = jarray_get(blacklistObj, i);
                        if (jis_string(entry)) {
                                raw_buffer entry_buf = jstring_get(entry);
                                if (g_strcmp0(entry_buf.m_str, app_name) == 0) {
                                        authorized = 0;
                                        jstring_free_buffer(entry_buf);
                                        goto end;
                                }
                                jstring_free_buffer(entry_buf);
                        }
                }
        }

        if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("whitelist"), &whitelistObj) && jis_array(whitelistObj)) {
                for (ssize_t i = 0; i < jarray_size(whitelistObj); i++) {
                        jvalue_ref entry = jarray_get(whitelistObj, i);
                        if (jis_string(entry)) {
                                raw_buffer entry_buf = jstring_get(entry);
                                if (g_strcmp0(entry_buf.m_str, app_name) == 0) {
                                        authorized = 1;
                                        jstring_free_buffer(entry_buf);
                                        goto end;
                                }
                                jstring_free_buffer(entry_buf);
                         }
                }
        }

end:
        j_release(&parsedObj);
        g_free(config_data);
        return authorized;
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
        const char *appName = LSMessageGetSenderServiceName(message);

        if (!is_app_authorized(appName)) {
                LSMessageReplyCustomError(sh, message, "Unauthorized service access");
                return true;
        }
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

	(void)g_strlcpy(hostnameTmp, hostname, strlen(hostname)+1);
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


static bool isInterfacePresent(char* interfaceName)
{
	struct ifaddrs *ifaddr, *ifa;
	if (getifaddrs(&ifaddr) == -1)
		return false;

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if(!g_strcmp0(interfaceName, ifa->ifa_name))
		{
			freeifaddrs(ifaddr);
			return true;
		}
	 }

	freeifaddrs(ifaddr);
	return false;
}
//->Start of API documentation comment block
/**
@page com_webos_nettools com.webos.nettools
@{
@section com_webos_nettools_addvlan addvlan

Set a vlanid for provided interface

@par Parameters
Name | Required | Type | Description
-----|--------|------|----------
vlanid	| yes	| String	| Vlan Id, range 1 ~ 4094
ifName	| yes	| String	| Interface on which to add the VLAN
method	| no	| String	| "dhcp", "manual" or "off"
address	| no	| String	| If specified, sets a new IP address (only when method is "manual")
netmask	| no	| String	| If specified, sets a new netmask (only when method is "manual")
gateway	| no	| String	| If specified, sets a new gateway IP address (only when method is "manual")


@par Returns(Call)
Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | Indicates the status of operation. Possible values are:
                              true - Indicates that the operation was successful.
                              false - Indicates that the operation failed.

@par Returns(Subscription)
None

@}
*/
//->End of API documentation comment block


/**
 *  @brief Handler for "addVlan" command.
 *
 *  JSON format:
 *  luna://com.webos.service.nettools/addVlan {"vlanid":<VLAN ID>, "ifName" : <Interface Name> }
 *
 */

static bool handleCreateVlan(LSHandle *sh, LSMessage *message, void* context)
{
	// Add any validation checks here

	// To prevent memory leaks, schema should be checked before the variables will be initialized.

	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
		j_cstr_to_buffer(STRICT_SCHEMA(PROPS_6(PROP(index, integer), OBJECT(interface, OBJSCHEMA_1(PROP(name, string))),
                                 PROP(method, string), PROP(address, string), PROP(netmask, string), PROP(gateway, string))
			REQUIRED_2(index, interface))), &parsedObj))
		return true;

	jvalue_ref vlanIdObj = {0},  interfaceObj= {0}, interfaceNameObj= {0}, methodObj = {0}, addressObj = {0}, netmaskObj = {0},
		   gatewayObj = {0};
	guint32 vlanId = 0;
	gchar *interfaceName = NULL;
	ipv4info_t ipv4 = {0};
	char addLink[80] = {0,};
	char addIPv4[90] = {0,};
	char vlan_interface[20] = {0,};
	// Parse vlanid
	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("index"),&vlanIdObj))
	{
		int vlan_id_num = 0;
		jnumber_get_i32(vlanIdObj, &vlan_id_num);
		if (vlan_id_num < 0 || vlan_id_num > 4094)
		{
			LSMessageReplyCustomErrorwithErrorcode(sh, message, "Vlanid does not have a valid data", VLAN_ERR_INVALID_VLAN_INDEX);
			goto exit;
		}
		else
			jnumber_get_i32(vlanIdObj, &vlanId);
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("interface"), &interfaceObj))
	{
		if (jobject_get_exists(interfaceObj, J_CSTR_TO_BUF("name"), &interfaceNameObj))
		{
			raw_buffer interfaceName_buf = jstring_get(interfaceNameObj);
			interfaceName = g_strdup(interfaceName_buf.m_str);
			jstring_free_buffer(interfaceName_buf);
		}
		else
		{
			LSMessageReplyCustomError(sh, message, "Could not validate json message against schema");
			goto exit;
		}
	}

	snprintf(vlan_interface, sizeof(vlan_interface), "%s.%d",interfaceName, vlanId);
	if(!isInterfacePresent(interfaceName))
	{
		LSMessageReplyCustomErrorwithErrorcode(sh, message, "Invalid Interface", VLAN_ERR_INVALID_INTERFACE);
		goto exit;
	}
	else if(isInterfacePresent(vlan_interface))
	{
		LSMessageReplyCustomErrorwithErrorcode(sh, message, "VLAN Index already Exist", VLAN_ERR_VLANID_EXISTS);
		goto exit;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("method"), &methodObj))
	{
		raw_buffer method_buf = jstring_get(methodObj);
		ipv4.method = g_strdup(method_buf.m_str);
		jstring_free_buffer(method_buf);

	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("address"), &addressObj))
	{
		raw_buffer address_buf = jstring_get(addressObj);
		ipv4.address = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);

		if (!is_valid_ipaddress(ipv4.address))
		{
			LSMessageReplyCustomErrorwithErrorcode(sh, message, "passed ipv4 address parameters does not have a valid data", VLAN_ERR_INVALID_ADDRESS);
			goto exit;
		}
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("netmask"), &netmaskObj))
	{
		raw_buffer netmask_buf = jstring_get(netmaskObj);
		ipv4.netmask = g_strdup(netmask_buf.m_str);
		jstring_free_buffer(netmask_buf);

		if (!is_valid_ipaddress(ipv4.netmask))
		{
			LSMessageReplyCustomErrorwithErrorcode(sh, message, "passed netmask parameters does not have a valid data", VLAN_ERR_INVALID_NETMASK);
			goto exit;
		}
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("gateway"), &gatewayObj))
	{
		raw_buffer gateway_buf = jstring_get(gatewayObj);
		ipv4.gateway = g_strdup(gateway_buf.m_str);
		jstring_free_buffer(gateway_buf);

		if (!is_valid_ipaddress(ipv4.gateway))
		{
			LSMessageReplyCustomErrorwithErrorcode(sh, message, "passed gateway parameters does not have a valid data", VLAN_ERR_INVALID_NETMASK);
			goto exit;
		}
	}

	if (!g_strcmp0(ipv4.method, "manual"))
	{

		if (ipv4.address == NULL || ipv4.netmask == NULL || ipv4.gateway == NULL)
				LSMessageReplyCustomErrorwithErrorcode(sh, message, "Address, netmask as well as gateway should be specified for out of range networks", VLAN_ERR_MSG_PARSE_FAIL);

		else
		{
                        GError *error = NULL;
                        gint exit_status;
                        snprintf(addLink, sizeof(addLink), "ip link add link %s name %s.%d type vlan id %d",interfaceName, interfaceName, vlanId, vlanId);
                        gchar *cmd1[] = {"sh", "-c",addLink, NULL};
                        if(!g_spawn_sync(NULL, cmd1, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL,NULL, NULL,&exit_status,&error))
                        {
                                g_printerr("Error executing command: %s\n", error->message);
                                g_error_free(error);
                        }
                        gchar *cmd2[] = {"sh", "-c","ip link", NULL};
                        if(!g_spawn_sync(NULL, cmd2, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL,NULL, NULL,&exit_status,&error))
                        {
                                g_printerr("Error executing command: %s\n", error->message);
                                g_error_free(error);
                        }
                        snprintf(addIPv4, sizeof(addIPv4), "ifconfig %s.%d %s netmask %s broadcast %s",interfaceName, vlanId, ipv4.address, ipv4.netmask, ipv4.gateway);
                        gchar *cmd3[] = {"sh", "-c",addIPv4, NULL};
                        if(!g_spawn_sync(NULL, cmd3, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL,NULL, NULL,&exit_status,&error))
                        {
                                g_printerr("Error executing command: %s\n", error->message);
                                g_error_free(error);
                        }
			LSMessageReplySuccess(sh, message);
		}
	}
	else if ((ipv4.method == NULL) || (!g_strcmp0(ipv4.method, "dhcp")))
	{
                GError *error = NULL;
                gint exit_status;
                snprintf(addLink, sizeof(addLink), "ip link add link %s name %s.%d type vlan id %d",interfaceName, interfaceName, vlanId, vlanId);
                printf("Fun: %s Line: %d  addLink: %s ", __FUNCTION__, __LINE__, addLink);
                gchar *cmd1[] = {"sh", "-c",addLink, NULL};
                if(!g_spawn_sync(NULL, cmd1, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL,NULL, NULL,&exit_status,&error))
                {
                        g_printerr("Error executing command: %s\n", error->message);
                        g_error_free(error);
                }
                gchar *cmd2[] = {"sh", "-c","ip link", NULL};
                if(!g_spawn_sync(NULL, cmd2, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL,NULL, NULL,&exit_status,&error))
                {
                        g_printerr("Error executing command: %s\n", error->message);
                        g_error_free(error);
                }
		LSMessageReplySuccess(sh, message);
	}
	else
	{
		LSMessageReplyCustomErrorwithErrorcode(sh, message, "passed method does not exist", VLAN_ERR_INVALID_METHOD);
	}


exit:
	j_release(&parsedObj);
	g_free(ipv4.method);
	g_free(ipv4.address);
	g_free(ipv4.netmask);
	g_free(ipv4.gateway);
	return true;
}


//->Start of API documentation comment block
/**
@page com_webos_nettools com.webos.nettools
@{
@section com_webos_nettools_deletevlan deletevlan

Delete provided interface vlanid

@par Parameters
Name | Required | Type | Description
-----|--------|------|----------
vlanid	| yes	| String	| Vlan Id, range 1 ~ 4094
ifName	| yes	| String	| Interface on which to add the VLAN

@par Returns(Call)
Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | Indicates the status of operation. Possible values are:
                              true - Indicates that the operation was successful.
                              false - Indicates that the operation failed.

@par Returns(Subscription)
None

@}
*/
//->End of API documentation comment block


/**
 *  @brief Handler for "deleteVlan" command.
 *
 *  JSON format:
 *  luna://com.webos.service.nettools/deleteVlan {"vlanid":<VLAN ID>, "ifName" : <Interface Name> }
 *
 */

static bool handleDeleteVlan(LSHandle *sh, LSMessage *message, void* context)
{
	// Add any validation checks here

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
				j_cstr_to_buffer(STRICT_SCHEMA(PROPS_2(PROP(index, integer), OBJECT(interface, OBJSCHEMA_1(PROP(name, string))))
						REQUIRED_2(index, interface))), &parsedObj))
		return true;

	jvalue_ref vlanIdObj = {0},  interfaceObj= {0}, interfaceNameObj= {0};
	guint32 vlanId = 0;
	gchar *interfaceName = NULL;
	char vlan_interface[20] = {0,};
	char downLink[80] = {0,};
	char delDev[80] = {0,};

	// Parse vlanid
	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("index"),&vlanIdObj))
	{
		int vlan_id_num = 0;
		jnumber_get_i32(vlanIdObj, &vlan_id_num);
		if (vlan_id_num < 0 || vlan_id_num > 4094)
		{
			LSMessageReplyCustomErrorwithErrorcode(sh, message, "Vlanid does not have a valid data", VLAN_ERR_INVALID_VLAN_INDEX);
			goto exit;
		}
		else
			jnumber_get_i32(vlanIdObj, &vlanId);
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("interface"), &interfaceObj))
	{
		if (jobject_get_exists(interfaceObj, J_CSTR_TO_BUF("name"), &interfaceNameObj))
		{
			raw_buffer interfaceName_buf = jstring_get(interfaceNameObj);
			interfaceName = g_strdup(interfaceName_buf.m_str);
			jstring_free_buffer(interfaceName_buf);
		}
		else
		{
			LSMessageReplyCustomError(sh, message, "Could not validate json message against schema");
			goto exit;
		}
	}

	snprintf(vlan_interface, sizeof(vlan_interface), "%s.%d",interfaceName, vlanId);
	if(!isInterfacePresent(interfaceName))
	{
		LSMessageReplyCustomErrorwithErrorcode(sh, message, "Invalid Interface", VLAN_ERR_INVALID_INTERFACE);
		goto exit;
	}
	else if(!isInterfacePresent(vlan_interface))
	{
		LSMessageReplyCustomErrorwithErrorcode(sh, message, "VLAN Index does not Exist", VLAN_ERR_VLANID_DOESNOT_EXISTS);
		goto exit;
	}

	snprintf(downLink, sizeof(downLink), "ip link set dev %s.%d down", interfaceName, vlanId);
        GError *error = NULL;
        gint exit_status;
        gchar *cmd1[] = {"sh", "-c",downLink, NULL};
        if(!g_spawn_sync(NULL, cmd1, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL,NULL, NULL,&exit_status,&error))
        {
                g_printerr("Error executing command: %s\n", error->message);
                g_error_free(error);
        }

        snprintf(delDev, sizeof(delDev), "ip link delete %s.%d", interfaceName, vlanId);
        gchar *cmd2[] = {"sh", "-c",delDev, NULL};
        if(!g_spawn_sync(NULL, cmd2, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL,NULL, NULL,&exit_status,&error))
        {
                g_printerr("Error executing command: %s\n", error->message);
                g_error_free(error);
        }

        LSMessageReplySuccess(sh, message);

exit:

	j_release(&parsedObj);

	return true;
}



/**
 * com.webos.service.nettools service Luna Method Table
 */

static LSMethod nettools_methods[] = {
    { LUNA_METHOD_PING,                 handlePingCommand },
    { LUNA_METHOD_PINGV6,               handlePingV6Command },
    { LUNA_METHOD_ARPING,               handleArpingCommand },
    { LUNA_METHOD_RESOLVEHOSTNAME,      handleResolveHostnameCommand },
    { LUNA_METHOD_CHECKHTTP,            handleCheckHttpCommand },
    { LUNA_METHOD_GETHOSTNAME,          handleGetHostNameCommand },
    { LUNA_METHOD_SETHOSTNAME,          handleSetHostNameCommand },
    { LUNA_METHOD_ADDVLAN,              handleCreateVlan },
    { LUNA_METHOD_DELETEVLAN,           handleDeleteVlan },
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
