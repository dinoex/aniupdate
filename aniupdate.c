
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
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
#include <db.h>

#undef WITH_UDP
#define WITH_UDP
#undef WITH_UDP_PING
#define WITH_UDP_PING

#define	MAX_BUF		40000
#define	MIN_DELAY	2

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

void string_to_lowercase(char *buffer);
int string_compare(const char *s1, const char *s2);
int ed2klink_to_key(const char *ed2k_link, char **size, char **ed2k);

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
void config_read(void);
void config_check(void);

void localdb_cleanup(const char *name, time_t vaild_from);
void localdb_write(const char *name, const char *hash, const char *value);
void localdb_write_ed2k(const char *name, const char *size, const char *md4, const char *value);
char *localdb_read(const char *name, const char *hash);
char *localdb_read_ed2k(const char *name, const char *size, const char *md4);

void network_close(void);
void network_open(void);
void network_send(const char *buf, size_t len);
int network_recv(size_t len);

void anidb_logout(void);
void anidb_alive(void);
void anidb_login(void);
void anidb_ping(void);
void anidb_add(const char *ed2k_link, int edit);
char *anidb_mylist(const char *ed2k_link);
char *anidb_files(const char *ed2k_link);

void usage(void);
void command_config(int argc, const char *const *argv);
void command_options(int argc, const char *const *argv);
void command_run(int argc, const char *const *argv);
int main(int argc, const char *const *argv);

static const char *Config_file = NULL;
static const char *Server_name = NULL;
static const char *Files_db = NULL;
static const char *Mylist_db = NULL;
static const char *User = NULL;
static const char *Password = NULL;
static int Debug = NO;
static int Verbose = NO;
static int Add_state;
static int Add_viewed;
static int Cache_ignore;
static int Remote_port;
static int Local_port;

static int s = -1;
static struct sockaddr_in sock_in;
static struct sockaddr_in local_in;
static time_t next_send = 0;

static char rbuf[MAX_BUF];
static char sbuf[MAX_BUF];
static char fbuf[MAX_BUF];
static char kbuf[MAX_BUF];

static const char *Tag = NULL;
static char *session = NULL;
static char *status = NULL;
int Taglen = 0;

static long Config_box_anzahl;
CONFIG_TYP      Config_box[] = {
{ -1, { &Config_box_anzahl   }, "_Config_box_anzahl", NULL },
{ 1, { &Add_state            }, "Add_state",          "1" },
{ 1, { &Add_viewed           }, "Add_viewed",         NULL },
{ 1, { &Cache_ignore         }, "Cache_ignore",       NULL },
{ 0, { &Config_file          }, "Config_file",        ".aniupdate" },
{ 1, { &Debug                }, "Debug",              NULL },
{ 0, { &Files_db             }, "Files_db",           "files.db" },
{ 1, { &Local_port           }, "Local_port",         "9000" },
{ 0, { &Mylist_db            }, "Mylist_db",          "mylist.db" },
{ 0, { &Password             }, "Password",           NULL },
{ 1, { &Remote_port          }, "Remote_port",        "9000" },
{ 0, { &Server_name          }, "Server_name",        "anidb.ath.cx" },
{ 0, { &User                 }, "User",               NULL },
{ 1, { &Verbose              }, "Verbose",            NULL },
{ -1, { NULL }, NULL, NULL }
};


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
	work = strchr(ed2k_link, ':');
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

	*size = strdup(work + 1);
	end = strchr(*size, '|');
	if (end != NULL)
		*end = 0;

	/* 146810880| */
	work = strchr(work + 1, '|');
	if (work == NULL)
		return 5;

	*ed2k = strdup(work + 1);
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

#ifdef ENABLE_SEQUENCE_SEARCH
	for (i = 1L; config[i].typ != -1; i ++) {
		if (string_compare(config[i].name, key) == 0) {
#else
	{
		i = config_find(config, key);
		if (i > 0L) {
#endif
			switch (config[i].typ) {
			case CT_LOWER_STRING:
				string_to_lowercase(value);
				/* FALLTHROUGH */
				/*@fallthrough@*/
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
		}
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
config_read(void)
{
	const char *delimiter = "\r\n";
	char *buffer;
	char *line;

	buffer = local_read(Config_file);
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
localdb_cleanup(const char *name, time_t vaild_from)
{
	DB *db;
	DBT key, data;
	int ret, fd, st;
	time_t tv;

	db = dbopen(name, O_RDWR, 0644, DB_HASH, NULL);
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
			strncpy(fbuf,data.data, data.size);
			fbuf[data.size] = 0;
			tv = atol(fbuf);
			if (tv < vaild_from) {
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
localdb_write(const char *name, const char *hash, const char *value)
{
	DB *db;
	DBT key, data;
	char *hash2;
	int fd, st;

	db = dbopen(name, O_RDWR|O_CREAT, 0644, DB_HASH, NULL);
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
		key.data = strdup(hash);
		key.size = strlen(key.data);
		sprintf(fbuf, "%lu|%s", (long)time(NULL), value);
		data.data = fbuf;
		data.size = strlen(fbuf);
		db->put(db, &key, &data, 0);
		db->sync(db,0);
		free(hash2);
		st = flock(fd, LOCK_UN);
	} else {
		warnx("lock database %s failed", name);
	}
	db->close(db);
}

void
localdb_write_ed2k(const char *name, const char *size, const char *md4, const char *value)
{
	size_t len;

	len = snprintf(kbuf, MAX_BUF - 1, "%s|%s", size, md4);
	localdb_write(name, kbuf, value);
}

char *
localdb_read(const char *name, const char *hash)
{
	DB *db;
	DBT key, data;
	char *hash2;

	db = dbopen(name, O_RDONLY, 0644, DB_HASH, NULL);
	if (db == NULL) {
		if (errno == ENOENT)
			return NULL;
		err(EX_NOINPUT, "open database %s failed", name);
	}

	/* generate entry */
	hash2 = strdup(hash);
	if (hash2 == NULL)
		errx(EX_CANTCREAT, "out of mem for database");
	key.data = strdup(hash);
	key.size = strlen(key.data);
	data.data = fbuf;
	data.size = strlen(fbuf);
	db->get(db, &key, &data, 0);
	free(hash2);
	db->close(db);
	return fbuf;
}

char *
localdb_read_ed2k(const char *name, const char *size, const char *md4)
{
	size_t len;

	len = snprintf(kbuf, MAX_BUF - 1, "%s|%s", size, md4);
	return localdb_read(name, kbuf);
}


void
network_open(void)
{
	struct hostent *hp;
	struct in_addr iaddr;
	struct timeval resp_timeout = { 15, 0 };
	int x = 1;
	int rc;

	bzero((char *)&sock_in, sizeof(sock_in));

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
	sock_in.sin_len = sizeof(sock_in);
	memcpy(&sock_in.sin_addr, hp->h_addr_list[0],
		sock_in.sin_len);
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
	local_in.sin_len = sizeof(local_in);
	local_in.sin_family = sock_in.sin_family;
	local_in.sin_port = htons(Local_port);
	rc = bind(s, (struct sockaddr *)(&local_in), sizeof(local_in));
	if (rc < 0)
		err(EX_OSERR, "cannot bind");

//	if (connect(s, &sock_in, sock_in.sin_len) < 0)
	if (connect(s, (struct sockaddr *)(&sock_in), sizeof(sock_in)) < 0)
		err(EX_OSERR, "cannot connect");

}

void
network_close(void)
{
	int rc;
	rc = shutdown(s, SHUT_RDWR);
}

void
network_send(const char *buf, size_t len)
{
#ifdef USE_WRITE
	struct iovec iov[2];
#endif
	time_t now;
	long llen;
	long delay;

	if (len == 0)
		len = strlen(buf) + 1;
	llen = len;

	now = time(NULL);
	delay = next_send - now;
	if (delay > 0)
		sleep((unsigned)delay);

	if (Debug != NO)
		puts(buf);

#ifdef USE_WRITE
	iov[0].iov_base = buf;
	iov[0].iov_len = len;
	if (writev(s, iov, 1) != llen)
		err(EX_OSERR, "write failed");
#else
	if (send(s, buf, len, 0) != llen)
		err(EX_OSERR, "send failed");
#endif

	next_send = time(NULL) + MIN_DELAY;
}


int
network_recv(size_t len)
{
	long llen;

	if (len == 0)
		len = MAX_BUF - 1;

	bzero(rbuf, sizeof(rbuf));
#ifdef USE_READ
	llen = read(s, rbuf, len);
	if (llen < 0)
		err(EX_OSERR, "read %ld", llen);
#else
	llen = recv(s, rbuf, len, 0);
	if (llen < 0)
		err(EX_OSERR, "recv %ld", llen);
#endif

	if (llen == 0)
		network_recv(len);

	if (Debug != NO)
		puts(rbuf);

	return 0;
}


void
anidb_logout(void)
{
	size_t len;

	if (session != NULL) {
		len = snprintf(sbuf, MAX_BUF - 1, "LOGOUT s=%s&tag=%s\n",
			session, Tag);
		session = NULL;
		network_send(sbuf, len);
		network_recv(0);

		status = rbuf + Taglen;
		if ((status[0] != '2') && (status[0] != '4')) {
			/* try to close all sessions */
			network_send("LOGOUT\n", 0);
			network_recv(0);
		}
	}
}

void
anidb_alive(void)
{
	size_t len;

#ifndef WITH_UDP
	/* TCP gives a welcome */
	network_recv(0);
	status = rbuf;
	if (status[0] != '1') 
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
anidb_login(void)
{
	size_t len;
	char *work;

	Tag = User;
	Taglen = strlen(Tag) + 1;
	len = snprintf(sbuf, MAX_BUF - 1,
		"AUTH user=%s&pass=%s&protover=2&client=aniupdate&clientver=1&tag=%s\n",
		User, Password, Tag);
	network_send(sbuf, len);
	network_recv(0);
	status = rbuf + Taglen;
	if (status[0] == '6')
		errx(EX_TEMPFAIL, "Server returns: %-70.70s", rbuf);
	if (status[0] == '5') {
		if ((status[2] == '3') || (status[4] == '1'))
			errx(EX_SOFTWARE, "Server returns: %-70.70s", rbuf);
		errx(EX_NOUSER, "Server returns: %-70.70s", rbuf);
	}
	if (status[0] != '2')
		errx(EX_TEMPFAIL, "Server returns: %-70.70s", rbuf);

	if (status[2] == '1')
		warnx("Server returns: %-70.70s", rbuf);

	work = strchr(status, ' ');
	if (work == NULL)
		errx(EX_TEMPFAIL, "Server returns: %-70.70s", rbuf);

	session = strdup(work + 1);
	work = strchr(session, ' ');
	if (work != NULL)
		*work = 0;
}

void
anidb_ping(void)
{
	size_t len;

	len = snprintf(sbuf, MAX_BUF - 1, "PING tag=%s\n", Tag) + 1;
	network_send(sbuf, len);
	network_recv(0);
	status = rbuf + Taglen;
	if (status[0] != '3')
		warnx("Server returns: %-70.70s", rbuf);
}

void
anidb_add(const char *ed2k_link, int edit)
{
	char *size = NULL;
	char *md4 = NULL;
	const char *extra = "";
	size_t len;
	int rc;

	if (Verbose != NO)
		warnx("add: %-70.70s", ed2k_link);

	rc = ed2klink_to_key(ed2k_link,&size,&md4);
	if (rc != 0) {
		warnx("File not an ed2k link, error=%d in: %-70.70s", rc, ed2k_link);
		return;
	}
	if ((size == NULL) || (md4 == NULL))
		return;

#if 0
MYLISTADD size={int4 size}&ed2k={str ed2khash}[&state={int2 state}&viewed={boolean viewed}&source={str source}&storage={str storage}&other={str other}][&edit=1]
#endif

	if (edit != NO)
		extra = "&edit=1";
	len = snprintf(sbuf, MAX_BUF - 1, "MYLISTADD s=%s&size=%s&ed2k=%s&state=%d&viewed=%d%s&tag=%s\n",
		session, size, md4, Add_state, Add_viewed, extra, Tag) + 1;
	free(size);
	free(md4);
	network_send(sbuf, len);
	network_recv(0);
	status = rbuf + Taglen;
	if (status[0] == '2')
		return;
	warnx("Server returns: %-70.70s", rbuf);
	if ((status[0] == '3') || (status[0] == '4'))
		return;
	if (status[0] != '5')
		return;
	if ((status[2] == '0') || (status[2] == '1')) {
		anidb_logout();
		anidb_login();
	}
}

char *
anidb_mylist(const char *ed2k_link)
{
	char *size = NULL;
	char *md4 = NULL;
	char *data;
	size_t len;
	int rc;

	if (Verbose != NO)
		warnx("add: %-70.70s", ed2k_link);

	rc = ed2klink_to_key(ed2k_link,&size,&md4);
	if (rc != 0) {
		warnx("File not an ed2k link, error=%d in: %-70.70s", rc, ed2k_link);
		return NULL;
	}
	if ((size == NULL) || (md4 == NULL))
		return NULL;

	if (Cache_ignore == NO) {
		data = localdb_read_ed2k(Mylist_db, size, md4);
		if (data != NULL)
			return data;
	}

	len = snprintf(sbuf, MAX_BUF - 1, "MYLIST s=%s&size=%s&ed2k=%s&tag=%s\n",
		session, size, md4, Tag) + 1;
	free(size);
	free(md4);
	network_send(sbuf, len);
	network_recv(0);
	status = rbuf + Taglen;
	if ((status[0] == '2') && (status[1] == '2') && (status[2] == '1')) {
		/* we have data */
		data = strchr(status, '\n');
		if (data == NULL)
			data = status + 3;
		localdb_write_ed2k(Mylist_db, size, md4, ++data);
		return data;
	}
	warnx("Server returns: %-70.70s", rbuf);
	if ((status[0] == '3') || (status[0] == '4'))
		return NULL;
	if (status[0] != '5')
		return NULL;
	if ((status[2] == '0') || (status[2] == '1')) {
		anidb_logout();
		anidb_login();
	}
	return NULL;
}

char *
anidb_files(const char *ed2k_link)
{
	char *size = NULL;
	char *md4 = NULL;
	char *data;
	size_t len;
	int rc;

	if (Verbose != NO)
		warnx("add: %-70.70s", ed2k_link);

	rc = ed2klink_to_key(ed2k_link,&size,&md4);
	if (rc != 0) {
		warnx("File not an ed2k link, error=%d in: %-70.70s", rc, ed2k_link);
		return NULL;
	}
	if ((size == NULL) || (md4 == NULL))
		return NULL;

	if (Cache_ignore == NO) {
		data = localdb_read_ed2k(Files_db, size, md4);
		if (data != NULL)
			return data;
	}

	len = snprintf(sbuf, MAX_BUF - 1, "FILE s=%s&size=%s&ed2k=%s&tag=%s\n",
		session, size, md4, Tag) + 1;
	free(size);
	free(md4);
	network_send(sbuf, len);
	network_recv(0);
	status = rbuf + Taglen;
	if ((status[0] == '2') && (status[1] == '2') && (status[2] == '0')) {
		/* we have data */
		data = strchr(status, '\n');
		if (data == NULL)
			data = status + 3;
		localdb_write_ed2k(Files_db, size, md4, ++data);
		return data;
	}
	warnx("Server returns: %-70.70s", rbuf);
	if ((status[0] == '3') || (status[0] == '4'))
		return NULL;
	if (status[0] != '5')
		return NULL;
	if ((status[2] == '0') || (status[2] == '1')) {
		anidb_logout();
		anidb_login();
	}
	return NULL;
}

#if 0

       by size+ed2k hash:
            MYLIST size={int4 size}&ed2k={str ed2khash} 


REPLY:

            221 MYLIST
            {int4 lid}|{int4 fid}|{int4 eid}|{int4 aid}|{int4 gid}|{int4 date}|{int2 state}|{int4 viewdate}|{str storage}|{str source}|{str other}
      OR
            321 NO SUCH ENTRY 


INFO:

      the state field provides information about the location and sharing state of a file in mylist.
      state:
          o 0 - unknown - state is unknown or the user doesnt want to provide this information
          o 1 - on hdd - the file is stored on hdd (but is not shared)
          o 2 - on cd - the file is stored on cd
          o 3 - deleted - the file has been deleted or is not available for other reasons (i.e. reencoded)
          o 4 - shared - the file is stored on hdd and shared
          o 5 - release - the file is stored on hdd and shared on release priority

      If files are added after hashing, a client should specify the state as 1 (on hdd) (if the user doesnt explicitly select something else). 




FILE size={int4 size}&ed2k={str ed2khash} 

REPLY:

            220 FILE
            {int4 fid}|{int4 aid}|{int4 eid}|{int4 gid}|{int4 state}|{int4 size}|{str ed2k}|{str anidbfilename}
      OR
            320 NO SUCH FILE 


INFO:

      fid, aid, eid, gid are the unique ids for the file, anime, ep, group entries at anidb.
      You can use those to create links to the corresponding pages at anidb.

      file state:
      bit / int value 	meaning
      1 / 1 	FILE_CRCOK: file matched official crc (displayed with green background in anidb)
      2 / 2 	FILE_CRCERR: file DID NOT match official crc (displayed with red background in anidb)
      3 / 4 	FILE_ISV2: file is version 2
      4 / 8 	FILE_ISV3: file is version 3
      5 / 16 	FILE_ISV4: file is version 4
      6 / 32 	FILE_ISV5: file is version 5


#endif




void usage(void)
{
	fprintf(stderr,
"\n"
" Usage: aniupdate [options] [...] commands [...]\n"
"\n"
" options:\n"
"--<name>=<value>  overrite config with given value\n"
"-debug            show datagramms\n"
"-f <config>       set name of config file, default '.aniudate'\n"
"-local <port>     set local port number, default 9000\n"
"-remote <port>    set remote port number, default 9000\n"
"-server <name>    set remote host, default anidb.ath.cx\n"
"-user             set userid\n"
"-verbose          show files processed\n"
"\n"
"\n"
" commands:\n"
"+ping                    test communication\n"
"+add ed2klink [...]      add files to mylist\n"
"+read ed2klink [...]     read mylist info\n"
"+write ed2klink [...]    write mylist info\n"
"+view ed2klink [...]     set files as viewed\n"
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
			case 'a': /* add to mylist */
			case 'e': /* edit mylist */
			case 'f': /* read from anidb */
			case 'p': /* ping */
			case 'r': /* read from mylist */
			case 'w': /* write to mylist */
				fc = ch;
				break;
			default:
				usage();
			}
			continue;
		}
		/* Arguments for */
		switch (fc) {
		case 'a':
		case 'e':
		case 'f':
		case 'r':
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

	while (--argc > 0) {
		cptr = *(++argv);
		if (*cptr == '-') {
			continue;
		}
		if (*cptr == '+') {
			ch = *(++cptr);
			switch (ch) {
			case 'p': /* ping */
				anidb_ping();
			case 'a': /* add to mylist */
			case 'e': /* edit mylist */
			case 'f': /* read from anidb */
			case 'r': /* read from mylist */
			case 'w': /* write to mylist */
				fc = ch;
				break;
			default:
				usage();
			}
			continue;
		}
		switch (fc) {
		case 'a':
			anidb_add(cptr, NO);
			break;
		case 'e':
			anidb_mylist(cptr);
			anidb_add(cptr, YES);
			break;
		case 'f':
			anidb_files(cptr);
			break;
		case 'r':
			anidb_mylist(cptr);
			break;
		case 'w':
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
	config_read();

	command_options(argc, argv);
	config_check();

	network_open();
	anidb_alive();
	anidb_login();

	command_run(argc, argv);

	anidb_logout();
	network_close();
	return 0;
}

