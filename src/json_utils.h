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


#ifndef JSONUTILS_H
#define JSONUTILS_H

#include <luna-service2/lunaservice.h>
#include <pbnjson.h>

// Build a schema as a const char * string without any execution overhead
#define SCHEMA_ANY                              "{}"
#define SCHEMA_1(param)                         "{\"type\":\"object\",\"properties\":{" param "},\"additionalProperties\":false}" // Ex: SCHEMA_1(REQUIRED(age,integer))

#define PROPS_1(p1)                             ",\"properties\":{" p1 "}"
#define PROPS_2(p1, p2)                         ",\"properties\":{" p1 "," p2 "}"
#define PROPS_3(p1, p2, p3)                     ",\"properties\":{" p1 "," p2 "," p3 "}"
#define PROPS_4(p1, p2, p3, p4)                 ",\"properties\":{" p1 "," p2 "," p3 "," p4 "}"
#define PROPS_5(p1, p2, p3, p4, p5)             ",\"properties\":{" p1 "," p2 "," p3 "," p4 "," p5 "}"
#define PROPS_6(p1, p2, p3, p4, p5, p6)         ",\"properties\":{" p1 "," p2 "," p3 "," p4 "," p5 "," p6 "}"
#define REQUIRED_1(p1)                          ",\"required\":[\"" #p1 "\"]"
#define REQUIRED_2(p1, p2)                      ",\"required\":[\"" #p1 "\",\"" #p2 "\"]"
#define STRICT_SCHEMA(attributes)               "{\"type\":\"object\"" attributes ",\"additionalProperties\":false}"
#define RELAXED_SCHEMA(attributes)              "{\"type\":\"object\"" attributes ",\"additionalProperties\":true}"

// Macros to use in place of the parameters in the SCHEMA_xxx macros above
#define PROP(name, type) "\"" #name "\":{\"type\":\"" #type "\"}"
#define ARRAY(name, type) "\"" #name "\":{\"type\":\"array\", \"items\":{\"type\":\"" #type "\"}}"
#define OBJSCHEMA_1(param)                         "{\"type\":\"object\",\"properties\":{" param "}}"
#define OBJSCHEMA_2(p1, p2)                        "{\"type\":\"object\",\"properties\":{" p1 "," p2 "}}"
#define OBJSCHEMA_3(p1, p2, p3)                    "{\"type\":\"object\",\"properties\":{" p1 "," p2 ", " p3 "}}"
#define OBJSCHEMA_4(p1, p2, p3, p4)                "{\"type\":\"object\",\"properties\":{" p1 "," p2 ", " p3 ", " p4 "}}"
#define OBJECT(name, objschema) "\"" #name "\":" objschema

#endif // JSONUTILS_H
