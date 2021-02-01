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
 * @file  nettools_service.h
 *
 */


#ifndef _NETTOOLS_SERVICE_H_
#define _NETTOOLS_SERVICE_H_

#include <luna-service2/lunaservice.h>

#define NETTOOLS_LUNA_SERVICE_NAME "com.webos.service.nettools"

/**
 * @name Luna Nettools Method Names
 * @{
 */
#define LUNA_METHOD_PING		"ping"
#define LUNA_METHOD_PINGV6		"ping6"
#define LUNA_METHOD_ARPING		"arping"
#define LUNA_METHOD_RESOLVEHOSTNAME	"resolvehostname"
#define LUNA_METHOD_CHECKHTTP		"checkhttp"
#define LUNA_METHOD_GETHOSTNAME		"gethostname"
#define LUNA_METHOD_SETHOSTNAME		"sethostname"
#define LUNA_METHOD_ADDVLAN             "createVlan"
#define LUNA_METHOD_DELETEVLAN          "deleteVlan"


#endif /* _NETTOOLS_SERVICE_H_ */


/**
 * IPv4 information structure for the service
 *
 * Includes method (auto/manual), ip address, prefix length and gateway address
 */
typedef struct ipv4info
{
	gchar *method;
	gchar *address;
	gchar *netmask;
	gchar *gateway;
} ipv4info_t;
