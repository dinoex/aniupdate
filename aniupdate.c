/*---------------------------------------------------------------------------

 Copyright (c) 2004
	by Dirk Meyer, All rights reserved.
	Im Grund 4, 34317 Habichtswald, Germany
	Email: dirk.meyer@dinoex.sub.org

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 3. Neither the name of the author nor the names of any co-contributors
    may be used to endorse or promote products derived from this software
    without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 SUCH DAMAGE.

-----------------------------------------------------------------------------

	aniupdate - udp client for http://anidb.net/
	============================================

	$Id$

----------------------------------------------------------------------------*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <sysexits.h>
#include <err.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#include <fcntl.h>
#ifdef linux
#include <db_185.h>
#else
#include <db.h>
#endif

#undef WITH_UDP
#define WITH_UDP
#undef WITH_UDP_PING
#define WITH_UDP_PING

#define	MAX_BUF		40000
#define	MAX_KEY		256
#define	MIN_DELAY	3
#define	MAX_DELAY	31

#define	NO		0
#define	YES		1
#define	GET_NEXT_DATA(x)	{ argv++; argc--; x = *argv; \
				if (x == NULL) usage(); }

#define CT_NO_DATA		-1L
#define CT_STRING		0
#define CT_INT			1
#define CT_LONG			2
#define CT_SIZE			3
#define CT_LOWER_STRING		4

#ifdef linux
#define	strlcpy(x,y,z)		{ strncpy(x,y,z);x[(z)-1]=0; }
#endif

typedef union {
	const void	*vvar;
	const char	**cvar;
	int		*ivar;
	long		*lvar;
	size_t		*tvar;
} VAR_POINTER;

typedef struct {
	const int	typ;
	VAR_POINTER	u;
	const char	*name;
	const char	*def;
} CONFIG_TYP;

typedef struct {
	char		*ml_size;
	char		*ml_md4;
	const char	*ml_cached;
	const char	*ml_lid;
	const char	*ml_fid;
	const char	*ml_eid;
	const char	*ml_aid;
	const char	*ml_gid;
	const char	*ml_date;
	const char	*ml_state;
	const char	*ml_viewdate;
	const char	*ml_storage;
	const char	*ml_source;
	const char	*ml_other;
} MYLIST_TYP;

void string_to_lowercase(char *buffer);
int string_compare(const char *s1, const char *s2);

FILE *file_open(const char *datei, const char *mode);
void file_seek(FILE *handle, long bytes, int mode);
long file_size(FILE *handle);
void file_read(void *buffer, size_t bytes, size_t count, FILE *handle);

char *local_read(const char *name);

void config_sorted(CONFIG_TYP *config);
void config_default(CONFIG_TYP *config);
long config_find(CONFIG_TYP *config, const char *key);
int config_set_var(CONFIG_TYP *config, const char *key, char *value);
void config_parse_line(CONFIG_TYP *config, const char *parameter);
void config_read(const char *filename);
void config_check(void);

void localdb_cleanup(const char *name, time_t valid_from);
void localdb_delete(const char *name, const char *hash);
void localdb_write(const char *name, const char *hash, const char *value);
void localdb_write_raw(const char *name, const char *hash, const char *value);
char *localdb_read(const char *name, const char *hash);

void network_save(void);
void network_close(void);
void network_open(void);
void network_retry(void);
void network_send(const char *buf, size_t len);
int network_recv(size_t len);

int ed2klink_to_key(const char *ed2k_link, char **size, char **ed2k);
int filename_to_key(const char *filename, char **size, char **ed2k);
int generate_hash(const char *filename, char **size, char **ed2k);
int mylist_decode(MYLIST_TYP *mylist, const char *ed2k_link, const char *data);
void print_date(const char *prefix, const char *seconds);
int mylist_edit(MYLIST_TYP *mylist, const char *changes);
int show_anidb(const char *const *info, const char *key, const char *data);

int anidb_status(void);
void anidb_nosession(void);
void anidb_logout(void);
void anidb_delay_login(void);
void anidb_login(void);
void anidb_alive(void);
void anidb_ping(void);
void anidb_add(const char *key, MYLIST_TYP *edit);
char *anidb_fetch(const char *db, const char *cmd, const char *key, int force);
char *anidb_animes(const char *key, int force);
char *anidb_episodes(const char *key, int force);
char *anidb_groups(const char *key, int force);
char *anidb_files(const char *key, int force);
char *anidb_mylist(const char *key, int force);

void usage(void);
void command_config(int argc, const char *const *argv);
void command_options(int argc, const char *const *argv);
void command_run(int argc, const char *const *argv);

static const char *Add_source = NULL;
static const char *Add_storage = NULL;
static const char *Add_other = NULL;
static const char *Config_file = NULL;
static const char *Date_format = NULL;
static const char *Server_name = NULL;
static const char *Session_db = NULL;
static const char *Files_db = NULL;
static const char *Hash_program = NULL;
static const char *Mylist_db = NULL;
static const char *Names_db = NULL;
static const char *Animes_db = NULL;
static const char *Episodes_db = NULL;
static const char *Groups_db = NULL;
static const char *User = NULL;
static const char *Password = NULL;
static int Debug = NO;
static int Verbose = NO;
static int Quiet = NO;
static int Add_state;
static int Add_viewed;
static int Batch_mode;
static int Cache_ignore;
static int Keep_session;
static int Local_port;
static int Remote_port;
static int Retrys;
static int Timeout;
static long Batch_count = 0;
static int Batch_error = 0;

static int connected = NO;
static int s = -1;
static struct sockaddr_in sock_in;
static struct sockaddr_in local_in;
static time_t next_send = 0;
static size_t retry_count = 0;
static size_t retry_len = 0;
static const char *retry_buf = NULL;
static unsigned long auth_delay = 0;
static int server_status = 0;

static char rbuf[MAX_BUF];
static char sbuf[MAX_BUF];
static char fbuf[MAX_BUF];
static char ebuf[MAX_BUF];
static char cbuf[MAX_KEY];
static char kbuf[MAX_KEY];
static char ksize[MAX_KEY];
static char khash[MAX_KEY];
static char kname[MAX_KEY];

static const char *tag = NULL;
static char *session = NULL;
int taglen = 0;

static const char C_[] = "";
static const char C_0[] = "0";
static const char C_SESSION[] = "session";
static const char C_NEXT_SEND[] = "next_send";
static const char C_CACHED[] = "cached";

static long Config_box_anzahl;
CONFIG_TYP Config_box[] = {
{ -1, { &Config_box_anzahl   }, "_Config_box_anzahl", NULL },
{ 0, { &Add_other            }, "Add_other",          C_ },
{ 0, { &Add_source           }, "Add_source",         C_ },
{ 1, { &Add_state            }, "Add_state",          "1" },
{ 0, { &Add_storage          }, "Add_storage",        C_ },
{ 1, { &Add_viewed           }, "Add_viewed",         NULL },
{ 0, { &Animes_db            }, "Animes_db",          "animes.db" },
{ 1, { &Batch_mode           }, "Batch_mode",         "0" },
{ 1, { &Cache_ignore         }, "Cache_ignore",       NULL },
{ 0, { &Config_file          }, "Config_file",        ".aniupdate" },
{ 0, { &Date_format          }, "Date_format",        "%Y-%m-%d %H:%M:%S" },
{ 1, { &Debug                }, "Debug",              NULL },
{ 0, { &Episodes_db          }, "Episodes_db",        "episodes.db" },
{ 0, { &Files_db             }, "Files_db",           "files.db" },
{ 0, { &Groups_db            }, "Groups_db",          "groups.db" },
{ 0, { &Hash_program         }, "Hash_program",       "edonkey-hash" },
{ 1, { &Keep_session         }, "Keep_session",       NULL },
{ 1, { &Local_port           }, "Local_port",         "9000" },
{ 0, { &Mylist_db            }, "Mylist_db",          "mylist.db" },
{ 0, { &Names_db             }, "Names_db",           "names.db" },
{ 0, { &Password             }, "Password",           NULL },
{ 1, { &Quiet                }, "Quiet",              NULL },
{ 1, { &Remote_port          }, "Remote_port",        "9000" },
{ 1, { &Retrys               }, "Retrys",             "2" },
{ 0, { &Server_name          }, "Server_name",        "localhost" },
{ 0, { &Session_db           }, "Session_db",         ".session.db" },
{ 1, { &Timeout              }, "Timeout",            "30" },
{ 0, { &User                 }, "User",               NULL },
{ 1, { &Verbose              }, "Verbose",            NULL },
{ -1, { NULL }, NULL, NULL }
};

static const char *response_mylist[] = {
	"lid",
	"fid",
	"eid",
	"aid",
	"gid",
	"date",
	"state",
	"viewdate",
	"storage",
	"source",
	"other"
};

static const char *response_file[] = {
	"fid",
	"aid",
	"eid",
	"gid",
	"state",
	"size",
	"ed2k",
	"anidbfilename"
};

static const char *response_anime[] = {
	"aid",
	"eps_total",
	"eps_normal",
	"eps_special",
	"rating",
	"votes",
	"tmprating",
	"itmpvotes",
	"review_rating",
	"reviews",
	"year",
	"type",
	"romaji",
	"kanji",
	"english",
	"other",
	"short_names",
	"synonyms",
	"category_list"
};

static const char *response_episode[] = {
	"eid",
	"aid",
	"length",
	"rating",
	"votes",
	"epno",
	"english",
	"romaji",
	"kanji"
};

static const char *response_group[] = {
	"gid",
	"rating",
	"votes",
	"acount",
	"fcount",
	"name",
	"short",
	"chan",
	"irc",
	"url"
};

#define	MYLIST_MAX_STATE	6
static const char *mylist_states[] = {
	"unknown",
	"on hdd",
	"on cd",
	"deleted",
	"shared",
	"release"
};

static const char *info_crc[] = {
	"unknown",
	"ok",
	"bad",
	"unknown"
};

typedef struct {
	unsigned int	crc:2;
	unsigned int	version:4;
	unsigned int	censored:2;
} INFO_STATE_TYP;

typedef union {
	unsigned int	numeric;
	INFO_STATE_TYP	value;
} INFO_STATE_CONVERT_TYP;

void
string_to_lowercase(char *buffer)
{
	char *work;

	if (buffer == NULL)
		return;
	for (work = buffer; *work != 0; work ++) {
		if (isupper(*work))
			*work = tolower(*work);
	}
}

int
string_compare(const char *s1, const char *s2)
{
	char c1;
	char c2;

	if (!s1)
		return s2 ? -1 : 0;
	if (!s2) return 1;

	do {
		c1 = *s1++;
		if (isupper(c1))
			c1 = tolower(c1);
		c2 = *s2++;
		if (isupper(c2))
			c2 = tolower(c2);
	} while (c1 && (c1 == c2));

	/*
	 * The following case analysis is necessary so that characters
	 * which look negative collate low against normal characters but
	 * high against the end-of-string NUL.
	 */

	if (c1 == c2)
		return 0;
	else if (c1 == '\0')
		return -1;
	else if (c2 == '\0')
		return 1;
	else
		return (c1 - c2);
}


FILE *
file_open(const char *datei, const char *mode)
{
	FILE *handle;

	if (datei == NULL)
		return (NULL);

	handle = fopen(datei, mode);
	if (handle == NULL) {
		if (errno != ENOENT)
			err(EX_NOINPUT, "cannot open file %s", datei);
	}
	return handle;
}

void
file_seek(FILE *handle, long bytes, int mode)
{
	int seek_status;

	seek_status = fseek(handle, bytes, mode);
	if (seek_status != 0)
		err(EX_IOERR, "cannot seek file, state=%d, pos=%ld, mode=%d",
			seek_status, bytes, mode);
}

long
file_size(FILE *handle)
{
	long size;

	file_seek(handle, 0L, SEEK_END);
	size = ftell(handle);
	file_seek(handle, 0L, SEEK_SET);
	if (size < 0L)
		err(EX_IOERR, "cannot read length of file, state=%ld",
			size);
	return size;
}

void
file_read(void *buffer, size_t bytes, size_t count, FILE *handle)
{
	size_t read_status;

	read_status = fread(buffer, bytes, count, handle);
	if (read_status != count)
		err(EX_IOERR, "cannot read %ld bytes from file, count=%ld got=%ld",
			(long)bytes, (long)count, (long)read_status);
}


char *
local_read(const char *name)
{
	size_t size;
	FILE *handle;
	char *buffer;

	handle = file_open(name, "rb");
	if (handle == NULL)
		return NULL;
	size = file_size(handle);
	buffer = malloc(size);
	file_read(buffer, size, 1, handle);
	fclose(handle);
	return buffer;
}


void
config_sorted(CONFIG_TYP *config)
{
	long i;
	int flag;

	for (i = 1L; config[i].typ != -1; i ++) {
		if (config[i + 1].typ == -1)
			break;
		flag = string_compare(config[i].name, config[i + 1].name);
		if (flag < 0)
			continue;

		errx(EX_CONFIG, "config structure defunct, <%s> >= <%s>",
			config[i].name, config[i + 1].name);
	};
	*(config[0].u.lvar) = i + 1;
}

void config_default(CONFIG_TYP *config)
{
	long i;

	config_sorted(config);
	for (i = 1L; config[i].typ != -1; i ++) {
		switch (config[i].typ) {
		case CT_STRING:
		case CT_LOWER_STRING:
			*(config[i].u.cvar) =
				config[i].def;
			break;
		case CT_INT:
			*(config[i].u.ivar) =
				(config[i].def != NULL ?
				atoi(config[i].def) : 0);
			break;
		case CT_LONG:
		case CT_SIZE:
			*(config[i].u.lvar) =
				(config[i].def != NULL ?
				atol(config[i].def) : 0);
			break;
		}
	}
}

long
config_find(CONFIG_TYP *config, const char *key)
{
	int how_far;
	long bin_mid;
	long bin_low;
	long bin_high;
	long anzahl;

	anzahl = *(config[0].u.lvar);
	if (anzahl > 0L) {
		bin_low = 0;
		bin_high = anzahl - 1;
		while (bin_low <= bin_high) {
			bin_mid = (bin_low + bin_high) / 2;
			how_far = string_compare(config[bin_mid].name, key);
			if (how_far == 0)
				return bin_mid;
			if (how_far < 0)
				bin_low = bin_mid + 1;
			else
				bin_high = bin_mid - 1;
		}
	};
	return CT_NO_DATA;
}

int
config_set_var(CONFIG_TYP *config, const char *key, char *value)
{
	long i;

	i = config_find(config, key);
	if (i > 0L) {
		switch (config[i].typ) {
		case CT_LOWER_STRING:
			string_to_lowercase(value);
			/* FALLTHROUGH */
		case CT_STRING:
			*(config[i].u.cvar) =
				value;
			break;
		case CT_INT:
			*(config[i].u.ivar) =
				atoi(value);
			break;
		case CT_LONG:
		case CT_SIZE:
			*(config[i].u.lvar) =
				atol(value);
			break;
		};
		return YES;
	};
	return NO;
}

void
config_parse_line(CONFIG_TYP *config, const char *parameter)
{
	int found;
	char *buffer;
	char *key;
	char *value;
	char *work;

	if (parameter[0] == '#')
		return;

	buffer = strdup(parameter);
	key = buffer;

	value = strchr(buffer, '=');
	if (value == NULL)
		errx(EX_CONFIG, "Key='%s' not found", buffer);
	*(value++) = 0;

	/* strip heading spaces */
	while ((*key != 0) && isspace(*key))
		key ++;
	while ((*value != 0) && isspace(*value))
		value ++;

	/* strip trailing spaces */
	work = key + strlen(key) - 1;
	while ((work >= key) && isspace(*work))
		*(work --) = 0;

	work = value + strlen(value) - 1;
	while ((work >= value) && isspace(*work))
		*(work --) = 0;

	/* escaped text */
	if (*value == '"') {
		value ++;
		work = strrchr(value, '"');
		if (work != NULL)
			*work = 0;
	}
		
	found = config_set_var(config, buffer, value);
	if (found != NO)
		return;

#ifndef ENABLE_EXTRA_KEYS
	errx(EX_CONFIG, "Key='%s' not found", buffer);
#endif
}

void
config_read(const char *filename)
{
	const char *delimiter = "\r\n";
	char *buffer;
	char *line;

	buffer = local_read(filename);
	if (buffer == NULL)
		return;

	line = strtok(buffer, delimiter);
	while (line != NULL) {
		config_parse_line(Config_box, line);
		line = strtok(NULL, delimiter);
	}
}

void
config_check(void)
{
	int fatal = NO;

	if (User == NULL) {
		warnx("User not set");
		fatal = YES;
	};
	if (Password == NULL) {
		warnx("Password not set");
		fatal = YES;
	};

	if (fatal != NO)
		errx(EX_CONFIG, "Please edit your configuration file");
}


void
localdb_cleanup(const char *name, time_t valid_from)
{
	DB *db;
	DBT key, data;
	int ret, fd, st;
	time_t tv;

	db = dbopen(name, O_RDWR, 0600, DB_HASH, NULL);
	if (db == NULL)
		err(EX_NOINPUT, "open database %s failed", name);

	/* lock all changes */
	fd = db->fd(db);
	if (fd == -1) {
		st = -1;
		warn("database has no fd");
	} else {
		st = flock(fd, LOCK_EX);
	}

	if (st == 0) {
		/* cleanup old entrys */
		ret = db->seq(db, &key, &data, R_FIRST);
		while (!ret) {
			data.size = data.size < 16 ? data.size : 15;
			strncpy(fbuf, data.data, data.size);
			fbuf[data.size] = 0;
			tv = atol(fbuf);
			if (tv < valid_from) {
				db->del(db, &key, 0);
				db->sync(db, 0);
				/* start over */
				ret = db->seq(db, &key, &data, R_FIRST);
				continue;
			}
			ret = db->seq(db, &key, &data, R_NEXT);
		}
		st = flock(fd, LOCK_UN);
	} else {
		warnx("lock database %s failed", name);
	}
	db->close(db);
}

void
localdb_delete(const char *name, const char *hash)
{
	DB *db;
	DBT key;
	char *hash2;
	int fd;
	int st;
	int rc;

	db = dbopen(name, O_RDWR|O_CREAT, 0600, DB_HASH, NULL);
	if (db == NULL)
		err(EX_NOINPUT, "open database %s failed", name);

	/* lock all changes */
	fd = db->fd(db);
	if (fd == -1) {
		st = -1;
		warn("database has no fd");
	} else {
		st = flock(fd, LOCK_EX);
	}

	if (st == 0) {
		/* generate entry */
		hash2 = strdup(hash);
		if (hash2 == NULL)
			errx(EX_CANTCREAT, "out of mem for database");
		key.data = hash2;
		key.size = strlen(key.data);
		rc = db->del(db, &key, 0);
		if ((rc != 0) && (rc != 1))
			warn("database delete returns %d", rc);
		db->sync(db,0);
		free(hash2);
		st = flock(fd, LOCK_UN);
	} else {
		warnx("lock database %s failed", name);
	}
	db->close(db);
}

void
localdb_write(const char *name, const char *hash, const char *value)
{
	DB *db;
	DBT key, data;
	char *hash2;
	int fd;
	int st;
	int rc;

	db = dbopen(name, O_RDWR|O_CREAT, 0600, DB_HASH, NULL);
	if (db == NULL)
		err(EX_NOINPUT, "open database %s failed", name);

	/* lock all changes */
	fd = db->fd(db);
	if (fd == -1) {
		st = -1;
		warn("database has no fd");
	} else {
		st = flock(fd, LOCK_EX);
	}

	if (st == 0) {
		/* generate entry */
		hash2 = strdup(hash);
		if (hash2 == NULL)
			errx(EX_CANTCREAT, "out of mem for database");
		key.data = hash2;
		key.size = strlen(key.data);
		snprintf(fbuf, MAX_BUF, "%lu|%s", (long)time(NULL), value);
		data.data = fbuf;
		data.size = strlen(fbuf);
		rc = db->put(db, &key, &data, 0);
		if ((rc != 0) && (rc != 1))
			warn("database write returns %d", rc);
		db->sync(db,0);
		free(hash2);
		st = flock(fd, LOCK_UN);
	} else {
		warnx("lock database %s failed", name);
	}
	db->close(db);
}

void
localdb_write_raw(const char *name, const char *hash, const char *value)
{
	DB *db;
	DBT key, data;
	char *hash2;
	int fd;
	int st;
	int rc;

	db = dbopen(name, O_RDWR|O_CREAT, 0600, DB_HASH, NULL);
	if (db == NULL)
		err(EX_NOINPUT, "open database %s failed", name);

	/* lock all changes */
	fd = db->fd(db);
	if (fd == -1) {
		st = -1;
		warn("database has no fd");
	} else {
		st = flock(fd, LOCK_EX);
	}

	if (st == 0) {
		/* generate entry */
		hash2 = strdup(hash);
		if (hash2 == NULL)
			errx(EX_CANTCREAT, "out of mem for database");
		key.data = hash2;
		key.size = strlen(key.data);
		if (value != NULL)
			snprintf(fbuf, MAX_BUF, "%s", value);
		data.data = fbuf;
		data.size = strlen(fbuf);
		rc = db->put(db, &key, &data, 0);
		if ((rc != 0) && (rc != 1))
			warn("database write returns %d", rc);
		db->sync(db,0);
		free(hash2);
		st = flock(fd, LOCK_UN);
	} else {
		warnx("lock database %s failed", name);
	}
	db->close(db);
}

char *
localdb_read(const char *name, const char *hash)
{
	DB *db;
	DBT key, data;
	char *hash2;
	char *str = NULL;
	int rc;

	db = dbopen(name, O_RDONLY, 0600, DB_HASH, NULL);
	if (db == NULL) {
		if (errno == ENOENT)
			return NULL;
		err(EX_NOINPUT, "open database %s failed", name);
	}

	/* generate entry */
	hash2 = strdup(hash);
	if (hash2 == NULL)
		errx(EX_CANTCREAT, "out of mem for database");
	key.data = hash2;
	key.size = strlen(key.data);
	data.data = NULL;
	data.size = 0;
	data.size = sizeof(fbuf) - 1;
	rc = db->get(db, &key, &data, 0);
	if (rc == 0) {
		if ((data.data != NULL) && (data.size > 0) && (data.size < sizeof(fbuf))) {
			strncpy(fbuf, data.data, data.size);
			fbuf[data.size] = 0;
			if (fbuf[data.size - 1] == '\n')
				fbuf[data.size - 1] = 0;
			str = fbuf;
		} else {
			warnx("database get failed, size = %d", data.size);
		}
	} else {
		if (rc != 1)
			warn("database read returns %d", rc);
	}
	free(hash2);
	db->close(db);
	return str;
}

void
network_save(void)
{
	time_t now;
	long delay;
	char ldata[20];

	now = time(NULL);
	delay = next_send - now;
	if (delay > 0) {
		snprintf(ldata, sizeof(ldata) - 1, "%lu", (unsigned long)next_send);
		localdb_write(Session_db, C_NEXT_SEND, ldata);
	} else {
		localdb_delete(Session_db, C_NEXT_SEND);
	}
}

void
network_close(void)
{
	int rc;

	if (connected == NO)
		return;

	rc = shutdown(s, SHUT_RDWR);
	connected = NO;

	network_save();
}

void
network_open(void)
{
	struct hostent *hp;
	struct in_addr iaddr;
	struct timeval resp_timeout = { 30, 0 };
	time_t saved;
	char *data;
	char *work;
	int x = 1;
	int rc;

	bzero((char *)&sock_in, sizeof(sock_in));
	resp_timeout.tv_sec = Timeout;

	iaddr.s_addr = inet_addr(Server_name);
	if (iaddr.s_addr != INADDR_NONE) {
		hp = gethostbyaddr((char *)&iaddr, sizeof(iaddr), AF_INET);
		errx(EX_NOHOST, "cannot resolve ip %s: %s",
			Server_name, hstrerror(h_errno));
	} else {
		hp = gethostbyname(Server_name);
		if (!hp)
			errx(EX_NOHOST, "cannot resolve %s: %s",
				Server_name, hstrerror(h_errno));

		if ((unsigned)hp->h_length > sizeof(sock_in.sin_addr) ||
				hp->h_length < 0)
			errx(1, "gethostbyname: illegal address");
	};
	sock_in.sin_family = hp->h_addrtype;
#ifndef linux
	sock_in.sin_len = sizeof(sock_in);
#endif
	memcpy(&sock_in.sin_addr, hp->h_addr_list[0],
		(unsigned)(hp->h_length));
	sock_in.sin_port = htons(Remote_port);

#ifdef WITH_UDP
	s = socket(sock_in.sin_family, SOCK_DGRAM, IPPROTO_UDP);
#else
	s = socket(sock_in.sin_family, SOCK_STREAM, IPPROTO_TCP);
#endif
	if (s < 0)
		err(EX_PROTOCOL, "cannot open socket");

	rc = setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &resp_timeout, sizeof(resp_timeout));
	if (rc < 0)
		err(EX_OSERR, "cannot set timeout");

	rc = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &x, sizeof(x));
	if (rc < 0)
		err(EX_OSERR, "cannot set addr");

#ifdef SO_REUSEPORT	/* doesnt exist everywhere... */
	rc = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, sizeof(x));
	if (rc < 0)
		err(EX_OSERR, "cannot set port");
#endif

	bzero((char *)&local_in, sizeof(local_in));
#ifndef linux
	local_in.sin_len = sizeof(local_in);
#endif
	local_in.sin_family = sock_in.sin_family;
	local_in.sin_port = htons(Local_port);
	rc = bind(s, (struct sockaddr *)(&local_in), sizeof(local_in));
	if (rc < 0)
		err(EX_OSERR, "cannot bind");

//	if (connect(s, &sock_in, sock_in.sin_len) < 0)
	if (connect(s, (struct sockaddr *)(&sock_in), sizeof(sock_in)) < 0)
		err(EX_OSERR, "cannot connect");

	connected = YES;

	next_send = time(NULL);
	data = localdb_read(Session_db, C_NEXT_SEND);
	if (data != NULL) {
		work = strchr(data, '|');
		if (work != NULL) {
			saved = atol(++work);
			if (saved > next_send)
				next_send = saved;
		}
	}
}

void
network_retry(void)
{
#ifdef USE_WRITE
	struct iovec iov[2];
#endif
	time_t now;
	long llen;
	long delay;

	if (retry_buf == NULL)
		err(EX_OSERR, "retry failed");

	llen = retry_len;
	now = time(NULL);
	delay = next_send - now;
	if (delay > 0)
		sleep((unsigned int)delay);

	if (Debug != NO)
		puts(retry_buf);

#ifdef USE_WRITE
	iov[0].iov_base = retry_buf;
	iov[0].iov_len = retry_len;
	if (writev(s, iov, 1) != llen)
		err(EX_OSERR, "write failed");
#else
	if (send(s, retry_buf, retry_len, 0) != llen)
		err(EX_OSERR, "send failed");
#endif

	Batch_count ++;
	if ((Batch_mode != 0) || (Batch_count > 50))
		next_send = time(NULL) + MAX_DELAY;
	else
		next_send = time(NULL) + MIN_DELAY;
}

void
network_send(const char *buf, size_t len)
{
	if (connected == NO)
		network_open();

	if (len == 0)
		len = strlen(buf) + 1;
	retry_len = len;
	retry_count = Retrys;
	retry_buf = buf;
	network_retry();
}

int
network_recv(size_t len)
{
	fd_set set;
	struct timeval stimeout;
	long llen;

	if (connected == NO)
		network_open();

	if (len == 0)
		len = MAX_BUF - 1;

	FD_ZERO(&set);
	FD_SET(s, &set);
	stimeout.tv_sec = Timeout;
	stimeout.tv_usec = 0;
	if ( ( select( s + 1, &set, NULL, NULL, &stimeout ) ) <= 0 )  {
		warn("recv %ld", 0L);
		retry_count --;
		network_retry();
		return network_recv(len);
	}

	/* data to read ? */
	bzero(rbuf, sizeof(rbuf));
#ifdef USE_READ
	llen = read(s, rbuf, len);
#else
	llen = recv(s, rbuf, len, 0);
#endif
	if (llen < 0) {
#ifdef WITH_UDP
		if (errno == ECONNREFUSED) {
			next_send = time(NULL);
			next_send += 30 * 60;
			network_save();
			err(EX_TEMPFAIL, "recv %ld", llen);
		}
		if ((errno != EAGAIN) || (retry_count == 0) || (retry_len == 0))
			err(EX_OSERR, "recv %ld", llen);
		warn("recv %ld", llen);
		retry_count --;
		network_retry();
		return network_recv(len);
#else
		err(EX_OSERR, "recv %ld", llen);
#endif
	}

	if (llen == 0) {
		retry_count --;
		network_retry();
		return network_recv(len);
	}

	if (Debug != NO)
		puts(rbuf);

	return 0;
}


int
ed2klink_to_key(const char *ed2k_link, char **size, char **ed2k)
{
	char *work;
	char *end;

	*size = NULL;
	*ed2k = NULL;

/*

in:
ed2k://|file|[PM]Princess_Tutu_13[A0BC1BC8].avi|146810880|0436df97e7fe25b620edb25380717479|

out:
146810880
0436df97e7fe25b620edb25380717479

*/

	/* ed2k: */
	work = strcasestr(ed2k_link, "ed2k:");
	if (work == NULL)
		return 1;

	/* //| */
	work = strchr(work, '|');
	if (work == NULL)
		return 2;

	/* file| */
	work = strchr(work + 1, '|');
	if (work == NULL)
		return 3;

	/* [PM]Princess_Tutu_13[A0BC1BC8].avi| */
	work = strchr(work + 1, '|');
	if (work == NULL)
		return 4;

	strlcpy(ksize, work + 1, sizeof(ksize));
	*size = ksize;
	end = strchr(*size, '|');
	if (end != NULL)
		*end = 0;

	/* 146810880| */
	work = strchr(work + 1, '|');
	if (work == NULL)
		return 5;

	strlcpy(khash, work + 1, sizeof(khash));
	*ed2k = khash;
	end = strchr(*ed2k, '|');
	if (end != NULL)
		*end = 0;
	string_to_lowercase(*ed2k);

	/* 0436df97e7fe25b620edb25380717479| */
	work = strchr(work + 1, '|');
	if (work == NULL)
		return 6;

	return 0;
}

int
generate_hash(const char *filename, char **size, char **ed2k)
{
	int rc;
	FILE *fp;
	char *data;

	snprintf(ebuf, sizeof(ebuf) - 1, "%s '%s'",
		Hash_program, filename);
	fflush(stdout);
	fp = popen(ebuf, "r");
	if (fp == NULL)
		err(EX_IOERR, "cannot execute hash from program: %-70.70s", ebuf);
	data = fgets(fbuf, sizeof(fbuf) -1, fp);
	if (data == NULL)
		err(EX_IOERR, "cannot get hash from program: %-70.70s", ebuf);
	pclose(fp);
	rc = ed2klink_to_key(data, size, ed2k);
	if (rc == 0) {
		if ((*size != NULL) && (*ed2k != NULL))
			return 0;
	}
	warnx("File not an ed2k link, error=%d in: %-70.70s", rc, filename);
	return 1;
}

int
filename_to_key(const char *filename, char **size, char **ed2k)
{
	int rc;
	const char *base;
	char *data;

	if (strncmp(filename, kname, sizeof(kname)) == 0) {
		*size = ksize;
		*ed2k = khash;
		return 0;
	}
	strncpy(kname, filename, sizeof(kname) - 1);
	kname[sizeof(kname) - 1] = 0;

	rc = ed2klink_to_key(filename, size, ed2k);
	if (rc == 0) {
		if ((*size != NULL) && (*ed2k != NULL))
			return 0;
	}

	base = strrchr(filename, '/');
	if (base != NULL)
		base ++;
	else
		base = filename;

	data = localdb_read(Names_db, base);
	if (data != NULL) {
		rc = ed2klink_to_key(data, size, ed2k);
		if (rc == 0) {
			if ((*size != NULL) && (*ed2k != NULL))
				return 0;
		}
		warnx("File not an ed2k link, error=%d in: %-70.70s", rc, filename);
		return 1;
	}
	rc = generate_hash(filename, size, ed2k);
	if (rc == 0)
		localdb_write_raw(Names_db, base, NULL);
	return rc;
}

int
mylist_decode(MYLIST_TYP *mylist, const char *ed2k_link, const char *data)
{
	int rc;
	int state = 0;
	char *buffer;
	char *work;

	bzero((char *)mylist, sizeof(*mylist));
	rc = filename_to_key(ed2k_link,&(mylist->ml_size),&(mylist->ml_md4));
	if (rc != 0)
		return 1;

	buffer = strdup(data);
	if (buffer == NULL)
		errx(EX_CANTCREAT, "out of memory in mylist_decode: %-70.70s", ed2k_link);

	mylist->ml_cached = buffer;
	work = strchr(buffer, '|');
	while (work != NULL) {
		*(work++) = 0;
		switch (state++) {
		case 0:
			mylist->ml_lid = work;
			break;
		case 1:
			mylist->ml_fid = work;
			break;
		case 2:
			mylist->ml_eid = work;
			break;
		case 3:
			mylist->ml_aid = work;
			break;
		case 4:
			mylist->ml_gid = work;
			break;
		case 5:
			mylist->ml_date = work;
			break;
		case 6:
			mylist->ml_state = work;
			break;
		case 7:
			mylist->ml_viewdate = work;
			break;
		case 8:
			mylist->ml_storage = work;
			break;
		case 9:
			mylist->ml_source = work;
			break;
		case 10:
			mylist->ml_other = work;
			break;
		default:
			return 0;
		}
		if (*work == 0)
			return 0;
		work = strchr(work, '|');
	}
	return 0;
}

void
print_date(const char *prefix, const char *seconds)
{
	long lsec;
	time_t now;

	if (seconds == NULL)
		return;

	lsec = atol(seconds);
	if (lsec == 0)
		return;

	now = lsec;
	strftime(kbuf, sizeof(kbuf) - 1, Date_format, localtime(&now));
	printf("%stext: %s\n", prefix, kbuf);
}

int
mylist_edit(MYLIST_TYP *mylist, const char *changes)
{
	char *buffer;
	char *value;
	int i;
	char ch;

	if (changes == NULL)
		return EX_USAGE;

	buffer = strdup(changes);
	if (buffer == NULL)
		errx(EX_CANTCREAT, "out of memory in mylist_edit: %-70.70s", changes);

	value = strchr(buffer, '=');
	if (value == NULL)
		return EX_USAGE;

	*(value++) = 0;

	if (strlen(buffer) == 0)
		return EX_USAGE;

	ch = *buffer;
	switch (ch) {
	case 'o': /* edit other */
		mylist->ml_other = value;
		return 0;
	case 's':
		if (strcmp(buffer,"source") == 0) {
			mylist->ml_source = value;
			return 0;
		};
		if (strcmp(buffer,"storage") == 0) {
			mylist->ml_storage = value;
			return 0;
		};
		if (strcmp(buffer,"state") == 0) {
                        for ( i=0; i < MYLIST_MAX_STATE; i++ ) {
				if ( string_compare( mylist_states[i], value ) != 0 )
					continue;
				snprintf( value, 2, "%1d", i );
				break;
			}
			mylist->ml_state = value;
			return 0;
		};
		break;
	}
	return EX_USAGE;
}

int
show_anidb(const char *const *info, const char *key, const char *data)
{
	char *buffer;
	char *work;
	char *field;
	char *size;
	char *md4;
	INFO_STATE_CONVERT_TYP decoder;
	int state = -2;
	int mylist = 0;
	int files = 0;
	int st = -1;
	int version = 1;
	int rc;

	buffer = strdup(data);
	if (buffer == NULL)
		errx(EX_CANTCREAT, "out of memory in info: %-70.70s", key);

	field = buffer;
	work = strchr(buffer, '|');
	while (work != NULL) {
		*(work++) = 0;
		switch (++state) {
		case -1:
			if (strstr(info[0],"lid")) {
				mylist ++;
			}
			if (strstr(info[0],"fid")) {
				files ++;
			}
			if ((files != 0) || (mylist != 0)) {
				rc = filename_to_key(key, &size, &md4);
				if (rc != 0)
					return 1;
				printf("size: %s\n", size);
				printf("ed2khash: %s\n", md4);
			}
			printf("%s: %s\n", C_CACHED, field);
			print_date(C_CACHED, field);
			break;
		default:
			printf("%s: %s\n", info[state], field);
			if (strstr(info[state],"date")) {
				print_date(info[state], field);
			};
			if (strstr(info[state],"state")) {
				st = atoi(field);
				if (mylist != 0) {
					if ((st >= 0) && (st < MYLIST_MAX_STATE))
						printf("statetext: %s\n", mylist_states[st]);
				}
				if (files != 0) {
					decoder.numeric = st;
					printf("crc: %s\n", info_crc[decoder.value.crc]);
					switch (decoder.value.version) {
					case 1:
						version = 2;
						break;
					case 2:
						version = 3;
						break;
					case 4:
						version = 4;
						break;
					case 8:
						version = 5;
						break;
					}
					printf("version: %d\n", version);
					if (decoder.value.censored == 1)
						printf("censored: uncut\n");
					if (decoder.value.censored == 2)
						printf("censored: censored\n");
				}
			};
			break;
		}
		field = work;
		work = strchr(work, '|');
	}
	if ( state >= 0 )
		printf("%s: %s\n", info[++state], field);
	printf("\n");
	return 0;
}

int
anidb_status(void)
{
	char *work;

	work = rbuf;
	if (taglen > 1) {
		if (strncmp(rbuf, tag, (size_t)(taglen -1)) == 0)
			work += taglen;
	}

	server_status = atoi(work);
	return server_status;
}

void
anidb_nosession(void)
{
	if (session == NULL)
		return;

	localdb_delete(Session_db, C_SESSION);
	session = NULL;
}

void
anidb_logout(void)
{
	size_t len;

	if (session == NULL)
		return;

	len = snprintf(sbuf, MAX_BUF - 1, "LOGOUT s=%s&tag=%s\n",
		session, tag);

	anidb_nosession();
	network_send(sbuf, len);
	network_recv(0);

	anidb_status();
	if ((server_status == 203) || (server_status == 403))
		return;

	/* try to close all sessions */
	network_send("LOGOUT\n", 0);
	network_recv(0);
}

void
anidb_delay_login(void)
{
	unsigned long add;
	unsigned long i;

	auth_delay++;
	if (auth_delay == 1) {
		next_send += 30;
		return;
	}
	if (auth_delay == 2) {
		next_send += 2 * 60;
		return;
	}
	if (auth_delay == 3) {
		next_send += 5 * 60;
		return;
	}
	if (auth_delay == 4) {
		next_send += 10 * 60;
		return;
	}
		
	add = 30 * 60;
	for (i=auth_delay; i > 4; i--) {
		add <<= 1;
	}
	next_send += add;
	network_save();
}

void
anidb_login(void)
{
	size_t len;
	char *work;
	char *data;
	time_t tv;
	time_t valid_from;

	if (session != NULL)
		anidb_nosession();

	tag = User;
	taglen = strlen(tag) + 1;
	data = localdb_read(Session_db, C_SESSION);
	if (data != NULL) {
		work = strchr(data, '|');
		if (work != NULL) {
			valid_from = time(NULL);
			valid_from -= (24 * 60 * 60);
			tv = atol(data);
			if (tv > valid_from) {
				session = strdup(++work);
				return;
			}
		}
	}

	len = snprintf(sbuf, MAX_BUF - 1,
		"AUTH user=%s&pass=%s&protover=3&client=aniupdate&clientver=2&tag=%s\n",
		User, Password, tag);
	network_send(sbuf, len);
	network_recv(0);

	anidb_status();
	switch (server_status) {
	case 200:
		Batch_error = 0;
		break;
	case 201:
		warnx("Server returns: %-70.70s", rbuf);
		Batch_error = 1;
		break;
	case 500:
	case 501:
	case 502:
	case 506:
		anidb_delay_login();
		errx(EX_NOUSER, "Server returns: %-70.70s", rbuf);
		break;
	case 503:
	case 504:
	case 505:
		anidb_delay_login();
		errx(EX_SOFTWARE, "Server returns: %-70.70s", rbuf);
		break;
	case 507:
	case 555:
	case 601:
	case 666:
		next_send += 30 * 60;
		network_save();
		/* FALLTHROUGH */
	default:
		errx(EX_TEMPFAIL, "Server returns: %-70.70s", rbuf);
		break;
	}

	work = strchr(rbuf + taglen, ' ');
	if (work == NULL)
		errx(EX_TEMPFAIL, "Server returns: %-70.70s", rbuf);

	session = strdup(work + 1);
	work = strchr(session, ' ');
	if (work != NULL)
		*work = 0;

	auth_delay = 0;
	localdb_write(Session_db, C_SESSION, session);
}

void
anidb_alive(void)
{
	size_t len;

#ifndef WITH_UDP
	/* TCP gives a welcome */
	network_recv(0);
	anidb_status();
	if (server_status != 100)
		errx(EX_TEMPFAIL, "Server returns: %-70.70s", rbuf);

#endif

#ifdef WITH_UDP
#ifdef WITH_UDP_PING
	len = snprintf(sbuf, MAX_BUF - 1, "PING\n") + 1;
	network_send(sbuf, len);
	network_recv(0);
#endif
#endif
}

void
anidb_ping(void)
{
	size_t len;

	len = snprintf(sbuf, MAX_BUF - 1, "PING tag=%s\n", tag) + 1;
	network_send(sbuf, len);
	network_recv(0);

	anidb_status();
	if (server_status != 300)
		warnx("Server returns: %-70.70s", rbuf);
}

char *
anidb_fetch(const char *db, const char *cmd, const char *key, int force)
{
	char *work;
	char *data;
	char *end;
	size_t len;

	if ((Cache_ignore == NO) && (force == NO) && (db != NULL)) {
		data = localdb_read(db, key);
		if (data != NULL)
			return data;
	}

	if (session == NULL)
		anidb_login();
	if (session == NULL)
		return NULL;

	len = snprintf(sbuf, MAX_BUF - 1, "%s&s=%s&tag=%s\n",
		cmd, session, tag) + 1;
	network_send(sbuf, len);
	network_recv(0);

	anidb_status();
	switch (server_status) {
	case 501:
	case 506:
		anidb_nosession();
		Batch_error = 1;
		return anidb_fetch(db, cmd, key, force);
	case 310:
	case 320:
	case 321:
	case 322:
	case 330:
	case 340:
	case 350:
		/* update vaild session */
		localdb_write(Session_db, C_SESSION, session);
		warnx("Server returns: %-70.70s", rbuf);
		if (server_status == 310)
			Batch_error = 0;
		else
			Batch_error = 2;
		return NULL;
	case 210:
	case 220:
	case 221:
	case 230:
	case 240:
	case 250:
	case 311:
		/* update vaild session */
		localdb_write(Session_db, C_SESSION, session);
		Batch_error = 0;
		break;
	case 507:
	case 555:
	case 601:
	case 666:
		next_send += 30 * 60;
		network_save();
		/* FALLTHROUGH */
	case 500:
	case 502:
		errx(EX_NOUSER, "Server returns: %-70.70s", rbuf);
	default:
		warnx("Server returns: %-70.70s", rbuf);
		Batch_error = 1;
		return NULL;
	}
	if (db == NULL)
		return rbuf;

	/* we have data */
	work = rbuf + taglen;
	data = strchr(work, '\n');
	if (data == NULL)
		data = work + 3;
	end = strchr(++data, '\n');
	if (end != NULL)
		*end = 0;
	localdb_write(db, key, data);
	return fbuf;
}

char *
anidb_animes(const char *key, int force)
{
	if (Verbose != NO)
		printf("animes: %-70.70s\n", key);

	snprintf(cbuf, MAX_BUF - 1, "ANIME aid=%s",
		key);
	return anidb_fetch(Animes_db, cbuf, key, force);
}

char *
anidb_episodes(const char *key, int force)
{
	if (Verbose != NO)
		printf("episodes: %-70.70s\n", key);

	snprintf(cbuf, MAX_BUF - 1, "EPISODE eid=%s",
		key);
	return anidb_fetch(Episodes_db, cbuf, key, force);
}

char *
anidb_groups(const char *key, int force)
{
	if (Verbose != NO)
		printf("groups: %-70.70s\n", key);

	snprintf(cbuf, MAX_BUF - 1, "GROUP gid=%s",
		key);
	return anidb_fetch(Groups_db, cbuf, key, force);
}

char *
anidb_files(const char *key, int force)
{
	char *size = NULL;
	char *md4 = NULL;
	int rc;

	if (Verbose != NO)
		printf("files: %-70.70s\n", key);

	rc = filename_to_key(key,&size,&md4);
	if (rc != 0)
		return NULL;

	snprintf(kbuf, sizeof(kbuf) - 1, "%s|%s", size, md4);
#if defined(WITH_BETA)
	snprintf(cbuf, MAX_BUF - 1, "FILE size=%s&ed2k=%s&fcode=33556239&acode=4195074",
		size, md4);
#else
	snprintf(cbuf, MAX_BUF - 1, "FILE size=%s&ed2k=%s",
		size, md4);
#endif
	return anidb_fetch(Files_db, cbuf, kbuf, force);
}

char *
anidb_mylist(const char *key, int force)
{
	char *size = NULL;
	char *md4 = NULL;
	int rc;

	if (Verbose != NO)
		printf("mylist: %-70.70s\n", key);

	rc = filename_to_key(key,&size,&md4);
	if (rc != 0)
		return NULL;

	snprintf(kbuf, sizeof(kbuf) - 1, "%s|%s", size, md4);
	snprintf(cbuf, MAX_BUF - 1, "MYLIST size=%s&ed2k=%s",
		size, md4);
	return anidb_fetch(Mylist_db, cbuf, kbuf, force);
}

void
anidb_add(const char *key, MYLIST_TYP *edit)
{
	char *size = NULL;
	char *md4 = NULL;
	int rc;

	if (Verbose != NO)
		printf("add: %-70.70s\n", key);

	rc = filename_to_key(key,&size,&md4);
	if (rc != 0)
		return;

	snprintf(kbuf, sizeof(kbuf) - 1, "%s|%s", size, md4);
	if (edit != NULL) {
		snprintf(cbuf, MAX_BUF - 1, "MYLISTADD size=%s&ed2k=%s&state=%s&viewed=%s"
			"&source=%s&storage=%s&other=%s&edit=1",
			size, md4, edit->ml_state, edit->ml_viewdate,
			edit->ml_source, edit->ml_storage, edit->ml_other);
	} else {
		snprintf(cbuf, MAX_BUF - 1, "MYLISTADD size=%s&ed2k=%s&state=%d&viewed=%d"
			"&source=%s&storage=%s&other=%s",
			size, md4, Add_state, Add_viewed,
			Add_source, Add_storage, Add_other);
	}
	anidb_fetch(NULL, cbuf, kbuf, 0);
}


void usage(void)
{
	fprintf(stderr,
"\n"
" Usage: aniupdate [options] [...] commands [...]\n"
"\n"
" options:\n"
"-debug            show datagramms\n"
"-verbose          show files processed\n"
"-quiet            don't print data\n"
"-f <config>       set name of config file, default '.aniudate'\n"
"--<name>=<value>  overrite config with given value\n"
"-local <port>     set local port number, default 9000\n"
"-remote <port>    set remote port number, default 9000\n"
"-server <name>    set remote host, default anidb.ath.cx\n"
"-user             set userid\n"
"\n"
" commands:\n"
"+ping                    test communication\n"
"+mylist ed2klink [...]   add files to mylist\n"
"+read ed2klink [...]     read mylist info\n"
"+view ed2klink [...]     set files as viewed (date will not be preserved)\n"
"+unview ed2klink [...]   set files as unviewed\n"
"+write key=value ed2klink [...]   change a field in mylist\n"
"+anime id [...]          read anime info\n"
"+episode id [...]        read episode info\n"
"+group id [...]          read group info\n"
"+file ed2klink [...]     read file info\n"
"\n"
"\n");
	exit(EX_USAGE);
}

void
command_config(int argc, const char *const *argv)
{
	const char *cptr;
	char ch;

	while (--argc > 0) {
		cptr = *(++argv);
		if (*cptr == '-') {
			ch = *(++cptr);
			switch (ch) {
			case 'd':
				Debug = YES;
				break;
			case 'f':
				GET_NEXT_DATA(cptr);
				Config_file = cptr;
				break;
			case 'q':
				Quiet = YES;
				break;
			case 'v':
				Verbose = YES;
				break;
			}
			continue;
		}
	}
}

void
command_options(int argc, const char *const *argv)
{
	const char *cptr;
	char ch;
	char fc = 0;

	while (--argc > 0) {
		cptr = *(++argv);
		if (*cptr == '-') {
			ch = *(++cptr);
			switch (ch) {
			case '-':
				config_parse_line(Config_box, ++cptr);
				break;
			case 'd':
				Debug = YES;
				break;
			case 'f':
				break;
			case 'l':
				GET_NEXT_DATA(cptr);
				Local_port = atol(cptr);
				break;
			case 'r':
				GET_NEXT_DATA(cptr);
				Remote_port = atol(cptr);
				break;
			case 'p':
				GET_NEXT_DATA(cptr);
				Password = cptr;
				break;
			case 'q':
				Quiet = YES;
				break;
			case 's':
				GET_NEXT_DATA(cptr);
				Server_name = cptr;
				break;
			case 'u':
				GET_NEXT_DATA(cptr);
				User = cptr;
				break;
			case 'v':
				Verbose = YES;
				break;
			default:
				usage();
			}
			continue;
		}
		/* Syntax Check */
		if (*cptr == '+') {
			ch = *(++cptr);
			switch (ch) {
			case 'w': /* edit mylist */
				GET_NEXT_DATA(cptr);
				break;
			case 'a': /* read anime from anidb */
			case 'e': /* read episode from anidb */
			case 'f': /* read file from anidb */
			case 'g': /* read group from anidb */
			case 'm': /* add to mylist */
			case 'p': /* ping */
			case 'r': /* read from mylist */
			case 'u': /* set unviewied in mylist */
			case 'v': /* set viewied in mylist */
				break;
			default:
				usage();
			}
			fc = ch;
			continue;
		}
		/* Arguments for */
		switch (fc) {
		case 'a':
		case 'e':
		case 'f':
		case 'g':
		case 'm':
		case 'r':
		case 'u':
		case 'v':
		case 'w':
			break;
		default:
			usage();
			break;
		}
	}
}


void
command_run(int argc, const char *const *argv)
{
	const char *cptr;
	char ch;
	char fc = 0;
	const char *data;
	MYLIST_TYP mylist_entry;
	const char *field = NULL;

	while (--argc > 0) {
		cptr = *(++argv);
		if (*cptr == '-') {
			continue;
		}
		if (*cptr == '+') {
			ch = *(++cptr);
			switch (ch) {
			case 'w': /* edit mylist */
				GET_NEXT_DATA(cptr);
				field = cptr;
				break;
			case 'p': /* ping */
				anidb_ping();
				break;
			case 'a': /* read anime from anidb */
			case 'e': /* read episode from anidb */
			case 'f': /* read file from anidb */
			case 'g': /* read group from anidb */
			case 'm': /* add to mylist */
			case 'r': /* read from mylist */
			case 'u': /* set unviewied in mylist */
			case 'v': /* set viewied in mylist */
				break;
			default:
				usage();
			}
			fc = ch;
			continue;
		}
		switch (fc) {
		case 'a':
			data = anidb_animes(cptr, NO);
			if (data == NULL)
				break;
			if (Quiet != NO)
				break;
			show_anidb(response_anime, cptr, data);
			break;
		case 'e':
			data = anidb_episodes(cptr, NO);
			if (data == NULL)
				break;
			if (Quiet != NO)
				break;
			show_anidb(response_episode, cptr, data);
			break;
		case 'f':
			data = anidb_files(cptr, NO);
			if (data == NULL)
				break;
			if (Quiet != NO)
				break;
			show_anidb(response_file, cptr, data);
			break;
		case 'g':
			data = anidb_groups(cptr, NO);
			if (data == NULL)
				break;
			if (Quiet != NO)
				break;
			show_anidb(response_group, cptr, data);
			break;
		case 'm':
			anidb_add(cptr, NULL);
			break;
		case 'r':
			data = anidb_mylist(cptr, NO);
			if (data == NULL)
				break;
			if (Quiet != NO)
				break;
			show_anidb(response_mylist, cptr, data);
			break;
		case 'w':
			data = anidb_mylist(cptr, NO);
			if (data == NULL)
				break;
			mylist_decode(&mylist_entry, cptr, data);
			if (mylist_edit(&mylist_entry, field) != 0)
				 usage();
			/* viewdate can't be preserved */
			if (strcmp(mylist_entry.ml_viewdate,C_0) != 0)
				mylist_entry.ml_viewdate = "1";
			anidb_add(cptr, &mylist_entry);
			data = anidb_mylist(cptr, YES);
			break;
		case 'u':
			data = anidb_mylist(cptr, NO);
			if (data == NULL)
				break;
			mylist_decode(&mylist_entry, cptr, data);
			mylist_entry.ml_viewdate = "0";
			anidb_add(cptr, &mylist_entry);
			anidb_mylist(cptr, YES);
			break;
		case 'v':
			data = anidb_mylist(cptr, NO);
			if (data == NULL)
				break;
			mylist_decode(&mylist_entry, cptr, data);
			if (strcmp(mylist_entry.ml_viewdate,C_0) != 0)
				break;
			mylist_entry.ml_viewdate = "1";
			anidb_add(cptr, &mylist_entry);
			anidb_mylist(cptr, YES);
			break;
		default:
			usage();
			break;
		}
	}
}

int
main(int argc, const char *const *argv)
{
	config_default(Config_box);
	command_config(argc, argv);
	config_read(Config_file);

	command_options(argc, argv);
	config_check();

//	anidb_alive();

	command_run(argc, argv);

	if (Keep_session == NO)
		anidb_logout();
	network_close();
	exit( Batch_error );
	return 0;
}

