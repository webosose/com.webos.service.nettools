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
 * @file  main.c
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <glib.h>
#include <pthread.h>
#include <stdbool.h>
#include <getopt.h>
#include <stdlib.h>
#include <luna-service2/lunaservice.h>

GMainLoop *mainloop = NULL;

int initialize_nettools_ls2_calls();

void term_handler(int signal)
{
	g_main_loop_quit(mainloop);
}

void handle_idle_timeout_cb(void *_)
{
	g_main_loop_quit(mainloop);
}

int main(int argc, char **argv)
{
	signal(SIGTERM, term_handler);
	signal(SIGINT, term_handler);

	mainloop = g_main_loop_new(NULL, FALSE);

	LSIdleTimeout(30000, handle_idle_timeout_cb, NULL, g_main_loop_get_context(mainloop));

	if (initialize_nettools_ls2_calls(mainloop) < 0)
	{
		g_error("Error in initializing com.webos.service.nettools service");
		return -1;
	}

	g_main_loop_run(mainloop);

	g_main_loop_unref(mainloop);

	return 0;
}
