/*
 * Copyright (C) 2015 Deutsche Telekom AG.
 *
 * Author: Mislav Novakovic <mislav.novakovic@sartura.hr>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <freenetconfd/plugin.h>
#include <freenetconfd/datastore.h>
#include <freenetconfd/freenetconfd.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include <utime.h>
#include <rpcd/plugin.h>

struct ubus_context *ubus_ctx;

__unused struct module *init();
__unused void destroy();

datastore_t root = DATASTORE_ROOT_DEFAULT;

struct module m;
char *_ns = "urn:ietf:params:xml:ns:yang:ietf-ip";
datastore_t *interfaces = NULL;
datastore_t *interfaces_state = NULL;
char *config_file = "network";

struct context {
	datastore_t *node;
	char *interface;
	bool ipv6;
};

static int timer = 10 * 1000;
void refresh_timer(struct uloop_timeout *t);
struct uloop_timeout uloop_timer = { .cb = refresh_timer };

static void update_interfaces(char *interface);

static int set_mtu_node(datastore_t *self, char *value)
{
	datastore_t *node = NULL;
	node = self->parent->parent;
	node = ds_find_child(self->parent->parent, "name", NULL);

	if (!node)
		return 0;

	pid_t pid=fork();
	if (pid==0) {
		DEBUG("/sbin/ifconfig ifconfig %s mtu %s up\n", node->value, value);
		execl("/sbin/ifconfig", "ifconfig", node->value, "mtu", value, "up", (char *) NULL);
		DEBUG("/usr/bin/ifconfig %s mtu %s up\n", node->value, value);
		execl("/usr/bin/ifconfig", node->value, "mtu", value, "up", (char *) NULL);
		exit(127);
	} else {
		waitpid(pid, 0, 0);
	}

	return 0;
}


static int get_interface_type(datastore_t *self)
{
	while (self) {
		if (!strcmp(self->name, "interfaces")) {
			return 1;
		} else if (!strcmp(self->name, "interfaces-state")) {
			return 2;
		}
		self = self->parent;
	}
	return 0;
}

static bool ifconfig(char *name, char *match)
{
	FILE *fp;
	char path[1035];
	bool result = false;

	if (!name)
		return false;

	// Open the command for reading
	char *script = "/usr/share/freenetconfd/network/interfaces_parameter.sh ";
	int len = strlen(script)+ strlen(name) +1;
	char command[len];
	snprintf(command, len, "%s%s", script, name);
	fp = popen(command, "r");
	if (fp == NULL) {
		printf("Failed to run command\n" );
		exit(1);
	}

	while (fgets(path, sizeof(path)-1, fp) != NULL) {
		char *pch = strstr(path, "error fetching interface information: Device not found");
		if(pch) {
			result = false;
			goto out;
		}
		if (match) {
			char *pch_match = strstr(path, match);
			if(pch_match) {
				result = true;
				goto out;
			}
		}
	}

	result = true;

out:
	pclose(fp);
	return result;
}

char *get_content(char *interface, char *file, int source)
{
	char *content = NULL;
	char buffer[256];
	FILE *fp = NULL;
	size_t length = 0;
	char *path = NULL;

	if (0 == source)
		path = "/sys/class/net/";
	else if (1 == source)
		path = "/proc/sys/net/ipv4/conf/";
	else if (2 == source)
		path = "/proc/sys/net/ipv6/conf/";
	else
		return NULL;

	int filename_len = (strlen(interface) + strlen(file) + strlen(path) + 2);
	char filename[filename_len];
	snprintf(filename, filename_len, "%s%s/%s", path, interface, file);

	fp = fopen(filename, "r");// do not use "rb"
	if(NULL == fp)
		return content;

	while (fgets(buffer, sizeof(buffer), fp)) {
		length = strlen(buffer) - 1;
		if (length >= 0 && buffer[length] == '\n')
			buffer[length] = '\0';

		content = strdup(buffer);
		break;
	}

out:
	if (fp)
		fclose (fp);
	return content;
}

char *get_formated_content(char *interface, char *file, int source)
{
	char *data = NULL;

	data = get_content(interface, file, source);
	if (!data)
		return strdup("");

	if (!strcmp(file, "carrier") || !strcmp(file, "forwarding") || !strcmp(file, "use_tempaddr")) {
		if (!strcmp(data, "1")) {
			free(data);
			return strdup("true");
		} else if (!strcmp(data, "0")) {
			free(data);
			return strdup("false");
		} else {
			free(data);
			return strdup("");
		}
	} else if (!strcmp(file, "speed")) {
		size_t len1 = strlen(data);
		char *add = "000000";
		size_t len2 = strlen(add);
		char *res = realloc(data, len1 + len2 + 1);
		if (res) {
			memcpy(res + len1, add, len2);
			res[len1 + len2] = 0;
			data = res;
		}
		return data;
	} else {
		return data;
	}
}

datastore_t *get_interface_name_node(datastore_t *self)
{
	datastore_t *result = NULL;
	while (self) {
		if (!strcmp(self->name, "interface")) {
			result = ds_find_child(self, "name", NULL);
			if (result);
				break;
		}
		self = self->parent;
	}
	return result;
}

static char *get_sys_node(datastore_t *self)
{
	datastore_t *node;
	char *data = NULL;

	node = get_interface_name_node(self);
	if (!node)
		return strdup("");

	if (!strcmp(self->name, "mtu")) {
		return get_formated_content(node->value, self->name, 0);
	} else if (!strcmp(self->name, "enabled")) {
		return get_formated_content(node->value, "carrier", 0);
	} else if (!strcmp(self->name, "oper-status")) {
		return get_formated_content(node->value, "operstate", 0);
	} else if (!strcmp(self->name, "if-index")) {
		return get_formated_content(node->value, "ifindex", 0);
	} else if (!strcmp(self->name, "phy-address")) {
		return get_formated_content(node->value, "address", 0);
	} else if (!strcmp(self->name, "speed")) {
		return get_formated_content(node->value, "speed", 0);
	} else if (!strcmp(self->name, "in-octets")) {
		return get_formated_content(node->value, "statistics/rx_bytes", 0);
	} else if (!strcmp(self->name, "in-discards")) {
		return get_formated_content(node->value, "statistics/rx_dropped", 0);
	} else if (!strcmp(self->name, "in-errors")) {
		return get_formated_content(node->value, "statistics/rx_errors", 0);
	} else if (!strcmp(self->name, "out-octets")) {
		return get_formated_content(node->value, "statistics/tx_bytes", 0);
	} else if (!strcmp(self->name, "out-discards")) {
		return get_formated_content(node->value, "statistics/tx_dropped", 0);
	} else if (!strcmp(self->name, "out-errors")) {
		return get_formated_content(node->value, "statistics/tx_errors", 0);
	} else if (!strcmp(self->name, "dup-addr-detect-transmits")) {
		return get_formated_content(node->value, "router_solicitations", 2);
	} else if (!strcmp(self->name, "temporary-valid-lifetime")) {
		return get_formated_content(node->value, "temp_valid_lft", 2);
	} else if (!strcmp(self->name, "temporary-preferred-lifetime")) {
		return get_formated_content(node->value, "temp_prefered_lft", 2);
	} else if (!strcmp(self->name, "create-temporary-addresses")) {
		return get_formated_content(node->value, "use_tempaddr", 2);
	} else if (!strcmp(self->name, "forwarding")) {
		if (!strcmp(self->parent->name, "ipv4"))
			return get_formated_content(node->value, "forwarding", 1);
		else if (!strcmp(self->parent->name, "ipv6"))
			return get_formated_content(node->value, "forwarding", 2);
		else
			return strdup("");
	} else {
		return strdup("");
	}
}

static datastore_t *create_ipv4_node(datastore_t *self, char *name, char *value, char *ns, char *target_name, int target_position)
{
	datastore_t *child = NULL;
	child = ds_add_child_create(self, name, value, NULL, NULL, 0);

	if (!strcmp(name, "enabled")) {
		//child->set = ;
		child->get = get_sys_node;
	} else if (!strcmp(name, "forwarding")) {
		child->get = get_sys_node;
		//child->get = ;
	} else if (!strcmp(name, "mtu")) {
		child->set = set_mtu_node;
		child->get = get_sys_node;
		//child->del = ;
	} else if (!strcmp(name, "address")) {
		//child->set = ;
		//child->get = ;
		//child->del = ;
		child->is_list = 1;
	} else if (!strcmp(name, "neighbour")) {
		//child->set = ;
		//child->get = ;
		//child->del = ;
		child->is_list = 1;
	} else {
		ds_free(child, 0);
		child = NULL;
	}

	return child;
}

static datastore_t *create_autocnf_node(datastore_t *self, char *name, char *value, char *ns, char *target_name, int target_position)
{
	datastore_t *child = NULL;
	child = ds_add_child_create(self, name, value, NULL, NULL, 0);

	if (!strcmp(name, "temporary-valid-lifetime")) {
		child->get = get_sys_node;
	} else if (!strcmp(name, "temporary-preferred-lifetime")) {
		child->get = get_sys_node;
	} else if (!strcmp(name, "create-temporary-addresses")) {
		child->get = get_sys_node;
	} else {
		ds_free(child, 0);
		child = NULL;
	}

	return child;
}


static datastore_t *create_ipv6_node(datastore_t *self, char *name, char *value, char *ns, char *target_name, int target_position)
{
	datastore_t *child = NULL;
	child = ds_add_child_create(self, name, value, NULL, NULL, 0);

	if (!strcmp(name, "enabled")) {
		//child->set = ;
		child->get = get_sys_node;
	} else if (!strcmp(name, "forwarding")) {
		child->get = get_sys_node;
		//child->get = ;
	} else if (!strcmp(name, "mtu")) {
		child->set = set_mtu_node;
		child->get = get_sys_node;
		//child->del = ;
	} else if (!strcmp(name, "address")) {
		//child->set = ;
		//child->get = ;
		//child->del = ;
		child->is_list = 1;
	} else if (!strcmp(name, "neighbour")) {
		//child->set = ;
		//child->get = ;
		//child->del = ;
		child->is_list = 1;
	} else if (!strcmp(name, "dup-addr-detect-transmits")) {
		child->get = get_sys_node;
	} else if (!strcmp(name, "autoconf")) {
		ds_free(child, 0);
		child = NULL;
		child = ds_add_child_create(self, name, NULL, _ns, NULL, 0);
		child = ds_add_child_create(self, name, value, NULL, NULL, 0);
		child->create_child = create_autocnf_node;
		return child;
	} else {
		ds_free(child, 0);
		child = NULL;
	}

	return child;
}

void add_strings(char **str1, const char *str2, char del)
{
	size_t len1 = *str1 ? strlen(*str1) : 0;
	size_t len2 = str2 ? strlen(str2) : 0;
	char *res = realloc(*str1, len1 + len2 + 2);
	if (res) {
		res[len1] = del;
		memcpy(res + len1 + 1, str2, len2);
		res[len1 + 1 + len2] = 0;
		*str1 = res;
	}
}

static char *get_router(char *interface)
{
	char *result = NULL;
	if (!interface)
		return result;

	datastore_t *address = NULL;
	datastore_t *node;
	char *data = NULL;
	FILE *fp = 0;
	char value[1024];
	char *script = NULL;

	script = "/usr/share/freenetconfd/network/router.sh";
	int len = strlen(script)+ strlen(interface) + 2;
	char command[len];
	snprintf(command, len, "%s %s", script, interface);
	fp = popen(command, "r");
	if (fp == NULL) {
		printf("Failed to run command\n" );
		return result;
	}

	while (fgets(value, sizeof(value)-1, fp) != NULL) {

		size_t ln = strlen(value) - 1;
		if (ln >= 0 && value[ln] == '\n')
			value[ln] = '\0';

		if (strlen(value) > 0)
			add_strings(&result, value, ' ');
	}

	pclose(fp);
	return result;
}

static char *get_status(char *interface, char *ip)
{
	char *result = "unknown";
	if (!ip || !interface)
		return strdup(result);

	datastore_t *address = NULL;
	datastore_t *node;
	char *data = NULL;
	FILE *fp = 0;
	char value[1024];
	char *script = NULL;

	script = "/usr/share/freenetconfd/network/status.sh";
	int len = strlen(script)+ strlen(interface) + strlen(ip) + 3;
	char command[len];
	snprintf(command, len, "%s %s %s", script, interface, ip);
	fp = popen(command, "r");
	if (fp == NULL) {
		printf("Failed to run command\n" );
		return strdup(result);
	}

	while (fgets(value, sizeof(value)-1, fp) != NULL) {

		size_t ln = strlen(value) - 1;
		if (ln >= 0 && value[ln] == '\n')
			value[ln] = '\0';

		if (strlen(value) > 0)
			result = value;
	}

	pclose(fp);
	return strdup(result);
}

void *update_ip_address(void *arg)
{
	struct context *ctx = (struct context*) arg;
	if (!ctx->node || !ctx->interface) {
		free(ctx);
		return NULL;
	}

	datastore_t *address = NULL;
	datastore_t *node;
	char *data = NULL;
	FILE *fp = 0;
	char value[1024];
	char *script = NULL;

	if (ctx->ipv6)
		script = "/usr/share/freenetconfd/network/ifconfig_6.sh";
	else
		script = "/usr/share/freenetconfd/network/ifconfig.sh";
	int len = strlen(script)+ strlen(ctx->interface) + 2;
	char command[len];
	snprintf(command, len, "%s %s", script, ctx->interface);
	fp = popen(command, "r");
	if (fp == NULL) {
		printf("Failed to run command\n" );
		goto out;
	}

	while (fgets(value, sizeof(value)-1, fp) != NULL) {

		size_t ln = strlen(value) - 1;
		if (ln >= 0 && value[ln] == '\n')
			value[ln] = '\0';

		char *pch = NULL;
		char value1[strlen(value) + 1], value2[strlen(value) + 1];
		pch = strchr(value, ' ');
		if (!pch)
			continue;
		snprintf(value1, (strlen(value) - strlen(pch) + 1), "%s", value);
		snprintf(value2, (strlen(pch)), "%s", (pch + 1));

		address = ds_add_child_create(ctx->node, "address", NULL, _ns, NULL, 0);
		address->is_list = 1;
		node = ds_add_child_create(address, "ip", value1, NULL, NULL, 0);
		node->is_key = 1;

		if (strlen(value2) <= 3 || ctx->ipv6)
			ds_add_child_create(address, "prefix-length", value2, NULL, NULL, 0);
		else
			ds_add_child_create(address, "netmask", value2, NULL, NULL, 0);

		if (2 == get_interface_type(ctx->node) && ctx->ipv6) {
			if (!strncmp(value1, "fe80:", 5))
				ds_add_child_create(address, "origin", "static", NULL, NULL, 0);
			else if (!strncmp(value1, "fd", 2))
				ds_add_child_create(address, "origin", "dynamic", NULL, NULL, 0);
			else
				ds_add_child_create(address, "origin", "other", NULL, NULL, 0);

			datastore_t *node = get_interface_name_node(ctx->node);
			char *data = NULL;
			if (node)
				data = get_status(node->value, value1);
			ds_add_child_create(address, "status", data, NULL, NULL, 0);
			free(data);
		}
	}

out:
	if (fp)
		pclose(fp);
	free(ctx);
	return NULL;
}

void *update_ip_neighbor(void *arg)
{
	struct context *ctx = (struct context*) arg;
	if (!ctx->node || !ctx->interface) {
		free(ctx);
		return NULL;
	}

	datastore_t *address = NULL;
	datastore_t *node;
	char *data = NULL;
	FILE *fp = 0;
	char value[1024];
	char *script = NULL;
	char *is_routers = NULL;

	if (ctx->ipv6)
		script = "/usr/share/freenetconfd/network/neighbor_6.sh";
	else
		script = "/usr/share/freenetconfd/network/neighbor.sh";
	int len = strlen(script)+ strlen(ctx->interface) + 2;
	char command[len];
	snprintf(command, len, "%s %s", script, ctx->interface);
	fp = popen(command, "r");
	if (fp == NULL) {
		printf("Failed to run command\n" );
		goto out;
	}

	if (1 == get_interface_type(ctx->node) && ctx->ipv6) {
		is_routers = get_router(ctx->interface);
	}

	while (fgets(value, sizeof(value)-1, fp) != NULL) {

		size_t ln = strlen(value) - 1;
		if (ln >= 0 && value[ln] == '\n')
			value[ln] = '\0';

		if (2 == get_interface_type(ctx->node) && ctx->ipv6) {
			char *pch = NULL;
			char value_ip[strlen(value) + 1];
			char value_lladr[strlen(value) + 1];
			char value_state[strlen(value) + 1];
			char *tmp = value;

			pch = strchr(tmp, ' ');
			if (!pch)
				continue;
			snprintf(value_ip, (strlen(tmp) - strlen(pch) + 1), "%s", tmp);
			tmp = (pch + 1);
			pch = strchr(tmp, ' ');
			if (!pch)
				continue;
			snprintf(value_lladr, (strlen(tmp) - strlen(pch) + 1), "%s", tmp);
			snprintf(value_state, (strlen(pch)), "%s", (pch + 1));

			address = ds_add_child_create(ctx->node, "neighbor", NULL, _ns, NULL, 0);
			address->is_list = 1;
			node = ds_add_child_create(address, "ip", value_ip, NULL, NULL, 0);
			node->is_key = 1;
			ds_add_child_create(address, "link-layer-address", value_lladr, NULL, NULL, 0);

			if (!strncmp(value_ip, "fe80:", 5))
				ds_add_child_create(address, "origin", "static", NULL, NULL, 0);
			else if (!strncmp(value_ip, "fd", 2))
				ds_add_child_create(address, "origin", "dynamic", NULL, NULL, 0);
			else
				ds_add_child_create(address, "origin", "other", NULL, NULL, 0);

			if (!strcmp(value_state, "STALE"))
				ds_add_child_create(address, "state", "stale", NULL, NULL, 0);
			else if (!strcmp(value_state, "REACHABLE"))
				ds_add_child_create(address, "state", "reachable", NULL, NULL, 0);
			else if (!strcmp(value_state, "DELAY"))
				ds_add_child_create(address, "state", "delay", NULL, NULL, 0);
			else if (!strcmp(value_state, "PROBE"))
				ds_add_child_create(address, "state", "probe", NULL, NULL, 0);
			else if (!strcmp(value_state, "INCOMPLETE"))
				ds_add_child_create(address, "state", "incomplete", NULL, NULL, 0);
			else
				ds_add_child_create(address, "state", "incomplete", NULL, NULL, 0);
		} else {
			char *pch = NULL;
			char *tmp = NULL;
			char value1[strlen(value) + 1], value2[strlen(value) + 1];
			pch = strchr(value, ' ');
			if (!pch)
				continue;
			snprintf(value1, (strlen(value) - strlen(pch) + 1), "%s", value);
			tmp = (pch + 1);
			pch = strchr(tmp, ' ');
			if (!pch)
				snprintf(value2, (strlen(tmp)), "%s", tmp);
			else
				snprintf(value2, (strlen(tmp) - strlen(pch) + 1), "%s", tmp);

			address = ds_add_child_create(ctx->node, "neighbor", NULL, _ns, NULL, 0);
			address->is_list = 1;
			node = ds_add_child_create(address, "ip", value1, NULL, NULL, 0);
			node->is_key = 1;
			ds_add_child_create(address, "link-layer-address", value2, NULL, NULL, 0);
			if (!strncmp(value1, "fe80:", 5))
				ds_add_child_create(address, "origin", "static", NULL, NULL, 0);
			else if (!strncmp(value1, "fd", 2))
				ds_add_child_create(address, "origin", "dynamic", NULL, NULL, 0);
			else
				ds_add_child_create(address, "origin", "other", NULL, NULL, 0);

			if (ctx->ipv6 && is_routers && strstr(is_routers, value1) != NULL) {
				ds_add_child_create(address, "is-router", "", NULL, NULL, 0);
			}
		}
	}

out:
	if (is_routers)
		free(is_routers);
	if (fp)
		pclose(fp);

	free(ctx);
	return NULL;
}

void *update_ipv4_interface(void *arg)
{
	struct context *ctx = (struct context*) arg;
	if (!ctx->node || !ctx->interface) {
		free(ctx);
		return NULL;
	}

	char *data = NULL;

	if (1 == get_interface_type(ctx->node)) {
		// leaf enabled
		data = get_formated_content(ctx->interface, "carrier", 0);
		ctx->node->create_child(ctx->node, "enabled", data, NULL, NULL, 0);
		free(data);
	}

	// leaf forwarding
	data = get_formated_content(ctx->interface, "forwarding", 1);
	ctx->node->create_child(ctx->node, "forwarding", data, NULL, NULL, 0);
	free(data);

	// leaf mtu
	data = get_formated_content(ctx->interface, "mtu", 0);
	ctx->node->create_child(ctx->node, "mtu", data, NULL, NULL, 0);
	free(data);

	pthread_t address_thread;
	pthread_t neighbor_thread;

	struct context *addr_ctx = calloc(1, sizeof(struct context));
	addr_ctx->node = ctx->node;
	addr_ctx->interface = ctx->interface;
	addr_ctx->ipv6 = false;

	struct context *nei_ctx = calloc(1, sizeof(struct context));
	nei_ctx->node = ctx->node;
	nei_ctx->interface = ctx->interface;
	nei_ctx->ipv6 = false;

	pthread_create(&address_thread, NULL, update_ip_address, addr_ctx);
	pthread_create(&neighbor_thread, NULL, update_ip_neighbor, nei_ctx);

	pthread_join(address_thread, NULL);
	pthread_join(neighbor_thread, NULL);

	free(ctx);
	return NULL;
}

void *update_ipv6_interface(void *arg)
{
	struct context *ctx = (struct context*) arg;
	if (!ctx->node || !ctx->interface) {
		free(ctx);
		return NULL;
	}

	char *data = NULL;

	if (1 == get_interface_type(ctx->node)) {
		// leaf enabled
		data = get_formated_content(ctx->interface, "carrier", 0);
		ctx->node->create_child(ctx->node, "enabled", data, NULL, NULL, 0);
		free(data);
	}

	// leaf forwarding
	data = get_formated_content(ctx->interface, "forwarding", 2);
	ctx->node->create_child(ctx->node, "forwarding", data, NULL, NULL, 0);
	free(data);

	// leaf mtu
	data = get_formated_content(ctx->interface, "mtu", 0);
	ctx->node->create_child(ctx->node, "mtu", data, NULL, NULL, 0);
	free(data);

	pthread_t address_thread;
	pthread_t neighbor_thread;

	struct context *addr_ctx = calloc(1, sizeof(struct context));
	addr_ctx->node = ctx->node;
	addr_ctx->interface = ctx->interface;
	addr_ctx->ipv6 = true;

	struct context *nei_ctx = calloc(1, sizeof(struct context));
	nei_ctx->node = ctx->node;
	nei_ctx->interface = ctx->interface;
	nei_ctx->ipv6 = true;

	pthread_create(&address_thread, NULL, update_ip_address, addr_ctx);
	pthread_create(&neighbor_thread, NULL, update_ip_neighbor, nei_ctx);

	pthread_join(address_thread, NULL);
	pthread_join(neighbor_thread, NULL);

	if (2 == get_interface_type(ctx->node)) {
		// leaf dup-addr-detect-transmits
		data = get_formated_content(ctx->interface, "router_solicitations", 2);
		ctx->node->create_child(ctx->node, "dup-addr-detect-transmits", data, NULL, NULL, 0);
		free(data);

		//autoconf
		datastore_t *node = ctx->node->create_child(ctx->node, "autoconf", NULL, _ns, NULL, 0);

		//create-temporary-addresses
		data = get_formated_content(ctx->interface, "use_tempaddr", 2);
		node->create_child(ctx->node, "create-temporary-addresses", data, NULL, NULL, 0);
		free(data);

		//temporary-valid-lifetime
		data = get_formated_content(ctx->interface, "temp_valid_lft", 2);
		node->create_child(ctx->node, "temporary-valid-lifetime", data, NULL, NULL, 0);
		free(data);

		//temporary-preferred-lifetime
		data = get_formated_content(ctx->interface, "temp_prefered_lft", 2);
		node->create_child(ctx->node, "temporary-preferred-lifetime", data, NULL, NULL, 0);
		free(data);
	}

	free(ctx);
	return NULL;
}

datastore_t *create_statistics_node(datastore_t *self, char *name, char *value, char *ns, char *target_name, int target_position)
{
	datastore_t *child = ds_add_child_create(self, name, value, NULL, NULL, 0);

	if (!strcmp(name, "discontinuity-time")) {
		child->get = get_sys_node;
	} else if (!strcmp(name, "in-octets")) {
		child->get = get_sys_node;
	} else if (!strcmp(name, "in-unicast-pkts")) {
		child->get = get_sys_node;
	} else if (!strcmp(name, "in-broadcast-pkts")) {
		child->get = get_sys_node;
	} else if (!strcmp(name, "in-multicast-pkts")) {
		child->get = get_sys_node;
	} else if (!strcmp(name, "in-discards")) {
		child->get = get_sys_node;
	} else if (!strcmp(name, "in-errors")) {
		child->get = get_sys_node;
	} else if (!strcmp(name, "in-unknown-protos")) {
		child->get = get_sys_node;
	} else if (!strcmp(name, "out-octets")) {
		child->get = get_sys_node;
	} else if (!strcmp(name, "out-unicast-pkts")) {
		child->get = get_sys_node;
	} else if (!strcmp(name, "out-broadcast-pkts")) {
		child->get = get_sys_node;
	} else if (!strcmp(name, "out-multicast-pkts")) {
		child->get = get_sys_node;
	} else if (!strcmp(name, "out-discards")) {
		child->get = get_sys_node;
	} else if (!strcmp(name, "out-errors")) {
		child->get = get_sys_node;
	} else {
		ds_free(child, 0);
		child = NULL;
	}

	return child;
}

datastore_t *create_interface_node(datastore_t *self, char *name, char *value, char *ns, char *target_name, int target_position)
{
	datastore_t *child = ds_add_child_create(self, name, value, NULL, NULL, 0);

	bool type = (2 == get_interface_type(self)) ? true : false;

	if (!strcmp(name, "name")) {
		//TODO child->get = ;
		//TODO child->set = ;
		//TODO child->del = ;
		child->is_key = 1;
	} else if (!strcmp(name, "description")) {
	} else if (!strcmp(name, "type")) {
	} else if (!strcmp(name, "enabled")) {
		//child->set = ;
		child->get = get_sys_node;
		//child->del = ;
	} else if (!strcmp(name, "ipv4")) {
		child->create_child = create_ipv4_node;
	} else if (!strcmp(name, "ipv6")) {
		child->create_child = create_ipv6_node;
	} else if (!type && strcmp(name, "enabled")) {
			child->get = get_sys_node;
	} else 	if (type && !strcmp(name, "admin-status")) {
		//child->set = ;
		//child->get = ;
		//child->del = ;
	} else if (type && !strcmp(name, "oper-status")) {
		child->get = get_sys_node;
	} else if (type && !strcmp(name, "last-change")) {
		//child->set = ;
		//child->get = ;
		//child->del = ;
	} else if (type && !strcmp(name, "if-index")) {
		child->get = get_sys_node;
	} else if (type && !strcmp(name, "phy-address")) {
		child->get = get_sys_node;
	} else if (type && !strcmp(name, "higher-layer-if")) {
		child->is_list = 1;
	} else if (type && !strcmp(name, "lower-layer-if")) {
		child->is_list = 1;
	} else if (type && !strcmp(name, "speed")) {
		child->get = get_sys_node;
	} else if (type && !strcmp(name, "statistics")) {
		ds_free(child, 0);
		child = NULL;
		child = ds_add_child_create(self, name, NULL, _ns, NULL, 0);
		child->create_child = create_statistics_node;
		return child;
	} else {
		ds_free(child, 0);
		child = NULL;
	}

	return child;
}

datastore_t *create_interfaces(datastore_t *self, char *name, char *value, char *ns, char *target_name, int target_position)
{
	datastore_t *child = ds_add_child_create(self, name, value, ns, target_name, target_position);

	if (!strcmp(name, "interface")) {
		child->is_list = 1;
		child->create_child = create_interface_node;
	} else {
		ds_free(child, 0);
		child = NULL;
	}

	return child;
}

void *update_interface_layer(void *arg)
{
	struct context *ctx = (struct context*) arg;
	if (!ctx->node || !ctx->interface) {
		free(ctx);
		return NULL;
	}

	char *data = NULL;
	FILE *fp = 0;
	char value[1024];
	char *script = NULL;

	script = "/usr/share/freenetconfd/network/interface_layer.sh";
	fp = popen(script, "r");
	if (fp == NULL) {
		printf("Failed to run command\n" );
		goto out;
	}

	while (fgets(value, sizeof(value)-1, fp) != NULL) {

		size_t ln = strlen(value) - 1;
		if (ln >= 0 && value[ln] == '\n')
			value[ln] = '\0';

		char *pch = NULL;
		char first[strlen(value) + 1], second[strlen(value) + 1];
		pch = strchr(value, ' ');
		if (!pch)
			continue;
		snprintf(first, (strlen(value) - strlen(pch) + 1), "%s", value);
		snprintf(second, (strlen(pch)), "%s", (pch + 1));

		if (!strcmp(first, "") || !strcmp(second, ""))
			continue;

		if (!strcmp(ctx->interface, first)) {
			ctx->node->create_child(ctx->node, "lower-layer-if", second, NULL, NULL, 0);
		} else if (!strcmp(ctx->interface, second)) {
			ctx->node->create_child(ctx->node, "higher-layer-if", first, NULL, NULL, 0);
		}
	}

out:
	if (fp)
		pclose(fp);
	free(ctx);
	return NULL;
}


void *update_interface(void *arg)
{
	datastore_t *node = NULL;
	datastore_t *child = NULL;
	datastore_t *tmp = NULL;
	char *data = NULL;

	char *interface = (char*) arg;
	DEBUG("interface -> %s\n", interface);

	// interface
	node = interfaces->create_child(interfaces, "interface", NULL, _ns, NULL, 0);
	if (!node)
		return NULL;
	child = node->create_child(node, "name", interface, NULL, NULL,0);
	child = node->create_child(node, "description", "", NULL, NULL, 0);
	if (!strcmp(interface, "lo"))
		child = node->create_child(node, "type", "softwareloopback", NULL, NULL, 0);
	else
		child = node->create_child(node, "type", "ethernetCsmacd", NULL, NULL, 0);
	data = get_formated_content(interface, "carrier", 0);
	node->create_child(node, "enabled", data, NULL, NULL, 0);
	free(data);

	child = node->create_child(node, "ipv4", NULL, _ns, NULL, 0);
	child->create_child = create_ipv4_node;

	pthread_t ipv4_intrface_thread;
	struct context *ipv4_ctx = calloc(1, sizeof(struct context));
	ipv4_ctx->node = child;
	ipv4_ctx->interface = interface;
	ipv4_ctx->ipv6 = false;

	pthread_create(&ipv4_intrface_thread, NULL, update_ipv4_interface, ipv4_ctx);

	child = ds_add_child_create(node, "ipv6", NULL, _ns, NULL, 0);
	child->create_child = create_ipv6_node;

	pthread_t ipv6_intrface_thread;
	struct context *ipv6_ctx = calloc(1, sizeof(struct context));
	ipv6_ctx->node = child;
	ipv6_ctx->interface = interface;
	ipv6_ctx->ipv6 = true;

	pthread_create(&ipv6_intrface_thread, NULL, update_ipv6_interface, ipv6_ctx);

	// interfaces-state
	node = interfaces->create_child(interfaces_state, "interface", NULL, _ns, NULL, 0);
	child = node->create_child(node, "name", interface, NULL, NULL,0);
	if (!strcmp(interface, "lo"))
		child = node->create_child(node, "type", "softwareloopback", NULL, NULL, 0);
	else
		child = node->create_child(node, "type", "ethernetCsmacd", NULL, NULL, 0);

	data = get_formated_content(interface, "operstate", 0);
	node->create_child(node, "oper-state", data, NULL, NULL, 0);
	free(data);

	data = get_formated_content(interface, "ifindex", 0);
	node->create_child(node, "if-index", data, NULL, NULL, 0);
	free(data);

	data = get_formated_content(interface, "address", 0);
	node->create_child(node, "phy-address", data, NULL, NULL, 0);
	free(data);

	data = get_formated_content(interface, "speed", 0);
	if (strcmp(data, ""))
		node->create_child(node, "speed", data, NULL, NULL, 0);
	free(data);

	pthread_t interface_layer_thread;

	struct context *interface_layer_ctx = calloc(1, sizeof(struct context));
	interface_layer_ctx->node = node;
	interface_layer_ctx->interface = interface;
	interface_layer_ctx->ipv6 = true;

	pthread_create(&interface_layer_thread, NULL, update_interface_layer, interface_layer_ctx);

	tmp = node->create_child(node, "statistics", NULL, _ns, NULL,0);
	data = get_formated_content(interface, "rx_bytes", 0);
	tmp->create_child(tmp, "in-octets", data, NULL, NULL, 0);
	free(data);
	data = get_formated_content(interface, "rx_dropped", 0);
	tmp->create_child(tmp, "in-discards", data, NULL, NULL, 0);
	free(data);
	data = get_formated_content(interface, "rx_errors", 0);
	tmp->create_child(tmp, "in-errors", data, NULL, NULL, 0);
	free(data);
	data = get_formated_content(interface, "tx_bytes", 0);
	tmp->create_child(tmp, "out-octets", data, NULL, NULL, 0);
	free(data);
	data = get_formated_content(interface, "tx_dropped", 0);
	tmp->create_child(tmp, "out-discards", data, NULL, NULL, 0);
	free(data);
	data = get_formated_content(interface, "tx_errors", 0);
	tmp->create_child(tmp, "out-errors", data, NULL, NULL, 0);
	free(data);

	child = ds_add_child_create(node, "ipv4", NULL, _ns, NULL, 0);
	child->create_child = create_ipv4_node;

	pthread_t ipv4_intrface_state_thread;
	struct context *ipv4_state_ctx = calloc(1, sizeof(struct context));
	ipv4_state_ctx->node = child;
	ipv4_state_ctx->interface = interface;
	ipv4_state_ctx->ipv6 = false;

	pthread_create(&ipv4_intrface_state_thread, NULL, update_ipv4_interface, ipv4_state_ctx);

	child = ds_add_child_create(node, "ipv6", NULL, _ns, NULL, 0);
	child->create_child = create_ipv6_node;

	pthread_t ipv6_intrface_state_thread;
	struct context *ipv6_state_ctx = calloc(1, sizeof(struct context));
	ipv6_state_ctx->node = child;
	ipv6_state_ctx->interface = interface;
	ipv6_state_ctx->ipv6 = true;

	pthread_create(&ipv6_intrface_state_thread, NULL, update_ipv6_interface, ipv6_state_ctx);

	pthread_join(interface_layer_thread, NULL);
	pthread_join(ipv6_intrface_thread, NULL);
	pthread_join(ipv6_intrface_state_thread, NULL);
	pthread_join(ipv4_intrface_thread, NULL);
	pthread_join(ipv4_intrface_state_thread, NULL);
	return NULL;
}

static void update_interfaces(char *interface)
{
	datastore_t *node = NULL;
	datastore_t *tmp = NULL;
	char *data = NULL;
	char path[1024];
	int ret, NTHREADS = 0, i = 0;
	DIR *dir;
	struct dirent* dirent;
	int num_interface = 0;

	node = interfaces->child;
	if (node) {
		while(node) {
			tmp = ds_find_child(node, "name", NULL);
			node = node->next;
			if (!interface || (interface && !strcmp(interface, tmp->value))) {
				ds_free(tmp->parent, 0);
				tmp = NULL;
			}
		}
	}

	node = interfaces_state->child;
	if (node) {
		while(node) {
			tmp = ds_find_child(node, "name", NULL);
			node = node->next;
			if (!interface || (interface && !strcmp(interface, tmp->value))) {
				ds_free(tmp->parent, 0);
				tmp = NULL;
			}
		}
	}

	dir = opendir("/sys/class/net/");
	if (!dir) {
		perror("Error in opendir");
		return;
	}
	while ((dirent = readdir(dir)) != 0) {
		if (!strcmp(dirent->d_name,".") || !strcmp(dirent->d_name, ".."))
			continue;
		num_interface++;
	}
	char *interfaces[num_interface];
	closedir(dir);

	dir = opendir("/sys/class/net/");
	if (!dir) {
		perror("Error in opendir");
		return;
	}
	while ((dirent = readdir(dir)) != 0) {
		if (!strcmp(dirent->d_name,".") || !strcmp(dirent->d_name, ".."))
			continue;
		interfaces[i++] = strdup(dirent->d_name);
		++NTHREADS;
	}

	pthread_t threads[(NTHREADS + 1)];
	for (i = 0; i < NTHREADS; ++i) {
		ret = pthread_create(&threads[i], NULL, update_interface, interfaces[i]);
		if (ret) {
			fprintf(stderr, "Error creating thread\n");
			continue;
		}

	}

	for (i = 0; i < NTHREADS; ++i) {
		ret = pthread_join(threads[i], NULL);
		free(interfaces[i]);
		if (ret) {
			fprintf(stderr, "Error closing thread\n");
			continue;
		}
	}

	closedir(dir);
}

void refresh_timer(struct uloop_timeout *t)
{
	update_interfaces(NULL);
	uloop_timeout_set(&uloop_timer, timer);
}

static void create_store()
{
	interfaces = ds_add_child_create(&root, "interfaces", NULL, _ns, NULL, 0);
	interfaces_state = ds_add_child_create(&root, "interfaces-state", NULL, _ns, NULL, 0);
	interfaces->create_child = create_interfaces;
	interfaces_state->create_child = create_interfaces;
	update_interfaces(NULL);
	uloop_timeout_set(&uloop_timer, timer);
}

struct rpc_method rpc[] = {
};

__unused struct module *init()
{
	m.rpcs = rpc;
	m.rpc_count = (sizeof(rpc) / sizeof(*(rpc)));
	m.ns = _ns;
	m.datastore = &root;

	create_store();

	return &m;
}

__unused void destroy()
{
	ds_free(root.child, 1);
	root.child = NULL;
}
