#include "cache.h"
#include "config.h"
#include "userdiff.h"
#include "attr.h"
#include "exec-cmd.h"
#include "repository.h"

static struct userdiff_driver *drivers;
static int ndrivers;
static int drivers_alloc;
static struct config_set gm_config;
static int config_init;
struct userdiff_driver *builtin_drivers;
static int builtin_drivers_size;

static int userdiff_config_init(void)
{
	int ret = -1;
	if (!config_init) {
		git_configset_init(&gm_config);
		if (the_repository && the_repository->gitdir)
			ret = git_configset_add_file(&gm_config, git_pathdup("userdiff"));

		// if .git/userdiff does not exist, set config_init to be -1
		if (ret == 0)
			config_init = 1;
		else
			config_init = -1;

		builtin_drivers = (struct userdiff_driver *) malloc(sizeof(struct userdiff_driver));
		builtin_drivers->name = "default";
		builtin_drivers->external = NULL;
		builtin_drivers->binary = -1;
		builtin_drivers->funcname.pattern = NULL;
		builtin_drivers->funcname.cflags = 0;
		builtin_drivers->word_regex = NULL;
		builtin_drivers->textconv_want_cache = 0;
		builtin_drivers->textconv = NULL;
		builtin_drivers->textconv_cache = NULL;
		builtin_drivers_size = 1;
	}
	return 0;
}

static char* join_strings(const struct string_list *strings)
{
	char* str;
	int i, len, length = 0;
	if (!strings)
		return NULL;

	for (i = 0; i < strings->nr; i++)
		length += strlen(strings->items[i].string);

	str = (char *) malloc(length + 1);
	length = 0;

	for (i = 0; i < strings->nr; i++) {
		len = strlen(strings->items[i].string);
		memcpy(str + length, strings->items[i].string, len);
		length += len;
	}
	str[length] = '\0';
	return str;
}

static struct userdiff_driver *userdiff_find_builtin_by_namelen(const char *k, int len)
{
	int i, key_length, word_regex_size;
	char *xfuncname_key, *word_regex_key, *xfuncname_value, *word_regex_value, *word_regex, *name;
	struct userdiff_driver *builtin_driver;
	char word_regex_extra[] = "|[^[:space:]]|[\xc0-\xff][\x80-\xbf]+";
	userdiff_config_init();
	name = (char *) malloc(len + 1);
	memcpy(name, k, len);
	name[len] = '\0';

	// look up builtin_driver
	for (i = 0; i < builtin_drivers_size; i++) {
		struct userdiff_driver *drv = builtin_drivers + i;
		if (!strncmp(drv->name, name, len) && !drv->name[len])
			return drv;
	}

	// if .git/userdiff does not exist and name is not "default", return NULL
	if (config_init == -1) {
		return NULL;
	}

	builtin_drivers_size++;
	builtin_drivers = realloc(builtin_drivers, builtin_drivers_size * sizeof(struct userdiff_driver));
	builtin_driver = builtin_drivers + builtin_drivers_size - 1;

	// load xfuncname and wordRegex from userdiff config file
	key_length = len + 16;
	xfuncname_key = (char *) malloc(key_length);
	word_regex_key = (char *) malloc(key_length);
	snprintf(xfuncname_key, key_length, "diff.%s.xfuncname", name);
	snprintf(word_regex_key, key_length, "diff.%s.wordRegex", name);
	xfuncname_value = join_strings(git_configset_get_value_multi(&gm_config, xfuncname_key));
	word_regex_value = join_strings(git_configset_get_value_multi(&gm_config, word_regex_key));
	free(xfuncname_key);
	free(word_regex_key);
	if (!xfuncname_value || !word_regex_value)
		return NULL;

	builtin_driver->name = name;
	builtin_driver->external = NULL;
	builtin_driver->binary = -1;
	builtin_driver->funcname.pattern = xfuncname_value;
	builtin_driver->funcname.cflags = REG_EXTENDED;
	builtin_driver->textconv_want_cache = 0;
	builtin_driver->textconv = NULL;
	builtin_driver->textconv_cache = NULL;
	word_regex_size = strlen(word_regex_value) + strlen(word_regex_extra) + 1;
	word_regex = (char *) malloc(word_regex_size);
	snprintf(word_regex, word_regex_size,
			"%s%s", word_regex_value, word_regex_extra);
	builtin_driver->word_regex = word_regex;
	return builtin_driver;
}

static struct userdiff_driver driver_true = {
	"diff=true",
	NULL,
	0,
	{ NULL, 0 }
};

static struct userdiff_driver driver_false = {
	"!diff",
	NULL,
	1,
	{ NULL, 0 }
};

static struct userdiff_driver *userdiff_find_by_namelen(const char *k, int len)
{
	int i;
	for (i = 0; i < ndrivers; i++) {
		struct userdiff_driver *drv = drivers + i;
		if (!strncmp(drv->name, k, len) && !drv->name[len])
			return drv;
	}
	return userdiff_find_builtin_by_namelen(k, len);
}

static int parse_funcname(struct userdiff_funcname *f, const char *k,
		const char *v, int cflags)
{
	if (git_config_string(&f->pattern, k, v) < 0)
		return -1;
	f->cflags = cflags;
	return 0;
}

static int parse_tristate(int *b, const char *k, const char *v)
{
	if (v && !strcasecmp(v, "auto"))
		*b = -1;
	else
		*b = git_config_bool(k, v);
	return 0;
}

static int parse_bool(int *b, const char *k, const char *v)
{
	*b = git_config_bool(k, v);
	return 0;
}

int userdiff_config(const char *k, const char *v)
{
	struct userdiff_driver *drv;
	const char *name, *type;
	int namelen;

	if (parse_config_key(k, "diff", &name, &namelen, &type) || !name)
		return 0;

	drv = userdiff_find_by_namelen(name, namelen);
	if (!drv) {
		ALLOC_GROW(drivers, ndrivers+1, drivers_alloc);
		drv = &drivers[ndrivers++];
		memset(drv, 0, sizeof(*drv));
		drv->name = xmemdupz(name, namelen);
		drv->binary = -1;
	}

	if (!strcmp(type, "funcname"))
		return parse_funcname(&drv->funcname, k, v, 0);
	if (!strcmp(type, "xfuncname"))
		return parse_funcname(&drv->funcname, k, v, REG_EXTENDED);
	if (!strcmp(type, "binary"))
		return parse_tristate(&drv->binary, k, v);
	if (!strcmp(type, "command"))
		return git_config_string(&drv->external, k, v);
	if (!strcmp(type, "textconv"))
		return git_config_string(&drv->textconv, k, v);
	if (!strcmp(type, "cachetextconv"))
		return parse_bool(&drv->textconv_want_cache, k, v);
	if (!strcmp(type, "wordregex"))
		return git_config_string(&drv->word_regex, k, v);

	return 0;
}

struct userdiff_driver *userdiff_find_by_name(const char *name)
{
	int len = strlen(name);
	return userdiff_find_by_namelen(name, len);
}

struct userdiff_driver *userdiff_find_by_path(struct index_state *istate,
					      const char *path)
{
	static struct attr_check *check;

	if (!check)
		check = attr_check_initl("diff", NULL);
	if (!path)
		return NULL;
	git_check_attr(istate, path, check);

	if (ATTR_TRUE(check->items[0].value))
		return &driver_true;
	if (ATTR_FALSE(check->items[0].value))
		return &driver_false;
	if (ATTR_UNSET(check->items[0].value))
		return NULL;
	return userdiff_find_by_name(check->items[0].value);
}

struct userdiff_driver *userdiff_get_textconv(struct repository *r,
					      struct userdiff_driver *driver)
{
	if (!driver->textconv)
		return NULL;

	if (driver->textconv_want_cache && !driver->textconv_cache) {
		struct notes_cache *c = xmalloc(sizeof(*c));
		struct strbuf name = STRBUF_INIT;

		strbuf_addf(&name, "textconv/%s", driver->name);
		notes_cache_init(r, c, name.buf, driver->textconv);
		driver->textconv_cache = c;
		strbuf_release(&name);
	}

	return driver;
}
