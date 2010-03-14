/* $Monkey: icblog.c,v 1.20 2004/09/24 13:50:21 nate Exp $ */
/*
 * Copyright (c) 2001-2004 Nathan L. Binkert <binkertn@umich.edu>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * http://www.icb.net/_jrudd/icb/protocol.html
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <libgen.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

/* Message types */
#define M_LOGIN         'a'	/* login packet */
#define M_LOGINOK       'a'	/* login packet */
#define M_OPEN          'b'	/* open msg to group */
#define M_PERSONAL      'c'	/* personal msg */
#define M_STATUS        'd'	/* status update message */
#define M_ERROR         'e'	/* error message */
#define M_IMPORTANT     'f'	/* special important announcement */
#define M_EXIT          'g'	/* tell other side to exit */
#define M_COMMAND       'h'	/* send a command from user */
#define M_CMDOUT        'i'	/* output from a command */
#define M_PROTO         'j'	/* protocol version information */
#define M_BEEP          'k'	/* beeps */
#define M_PING          'l'	/* ping packet */
#define M_PONG          'm'	/* return for ping packet */



#define BUFSIZE 4096
#define MAX_FIELDS 16

struct icb_packet {
	unsigned char   length;
	unsigned char   type;
	char            data[256];	/* One extra byte, in case we need to
					 * add NUL */
};

volatile sig_atomic_t sound_alarm = 0;
int             test = 0;
int             isfile = 0;
int             isdir = 0;
int             istrunc = 0;
int             isgmt = 0;
int             nofork = 0;
int             port = 7326;
FILE           *server = NULL;
char           *filename = NULL;
char           *group = "";
char           *username = "logger";
char           *nickname = "logger";
char            hostname[MAXHOSTNAMELEN + 1];
int             the_last_year;
int             the_last_month;
int             the_last_day;
time_t          the_time;
struct tm      *the_tm = NULL;
sigset_t        sigset_alrm;
char           *mailaddress = "root";

/* #define DEBUG */

#ifdef DEBUG
void
DPRINTF(const char *fmt,...)
{
	va_list         ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}
#define DUMP_PACKET(buf, len) dump_packet(buf, len)
#define DUMP_DATA(buf, len) dump_data(buf, len)
#else
static inline void
DPRINTF(const char *fmt,...)
{
}
#define DUMP_PACKET(buf, len)
#define DUMP_DATA(buf, len)
#endif

void            Send_Message(FILE * f, char mesgid, const char *field[], int nfields);
void 
Send_Login(FILE * f, const char *login, const char *nick,
	   const char *group, const char *command,
	   const char *passwd, const char *status,
	   const char *level);
void            Send_Ping(FILE * f, const char *MesgID);
void            Send_Pong(FILE * f, const char *MesgID);
void            Send_Command(FILE * f, const char *Command, const char *Message);
void 
Send_NickCommand(FILE * f, const char *Command, const char *Nick,
		 const char *Message);
void            Group_Message(FILE * f, const char *Message);
void            Personal_Message(FILE * f, const char *Nick, const char *Message);
void            Talk_Self(FILE * f, const char *Message);

int             select_server(FILE * f, int iswritem, int dosigs);
int             flush_server(FILE * f);
int             write_server(FILE * f, const void *buf, size_t len);
int             read_server(FILE * f, void *buf, size_t len, int do_sigs);
int             read_packet(FILE * f, void *buf, size_t len);
int             process_packet(FILE * f, void *buf, size_t len);
void            handle_signals(FILE * f);
void            dump_packet(const void *buf, size_t len);
void            dump_data(const void *buf, size_t len);

struct tm      *(*timefunc) (const time_t * clock) = localtime;

int             midnight = 0;

void
fatal(char *fmt,...)
{
	va_list         v;
	va_start(v, fmt);
	vfprintf(stderr, fmt, v);
	va_end(v);

	exit(1);
}

void
get_the_time()
{
	the_time = time(NULL);
	the_tm = timefunc(&the_time);
}

FILE           *output = stdout;
void
file_open(const char *fn)
{
	FILE           *f;

	f = fopen(fn, istrunc ? "w" : "a");

	if (f) {
		if (output && output != stdout)
			fclose(output);

		if (setvbuf(f, NULL, _IOFBF, 0)) {
			fclose(f);
			fatal("setvbuf");
		}
		output = f;
	}else {
		char            buf[64];
		strerror_r(errno, buf, sizeof buf);
		fatal("Could not open file '%s': %s\n", fn, buf);
	}
}

void
dir_time_open(const char *dir)
{
	char            buf[FILENAME_MAX + 1];

	snprintf(buf, sizeof(buf), "%s/%04d-%02d-%02d", dir,
		 the_tm->tm_year + 1900, the_tm->tm_mon + 1, the_tm->tm_mday);
	file_open(buf);
}

void
new_alarm()
{
#if 0
	int             next_day = 86400 -
	(((the_tm->tm_hour * 60) + the_tm->tm_min) * 60 + the_tm->tm_sec);
#endif

	int             next_hour = 3600 - (the_tm->tm_min * 60 + the_tm->tm_sec);

#if 0
	int             next_minute = 60 - the_tm->tm_sec;
#endif

	alarm(next_hour);
}

void
alarm_handler(int sigraised)
{
	sound_alarm = 1;
}

char           *progname;
void
usage()
{
	fprintf(stderr,
		"Usage: %s [-DGt] [-d dirname | -f filename] [-g groupname] [-n nickname]\n"
		"        [-p server port] [-u username] host\n"
		"\n"
		"        -D Don't fork. (For debugging)"
		"        -G Use GMT for times\n"
		"        -d Log to directory\n"
		"        -t truncate output file\n",
		basename(progname));
	exit(1);
}

void
Send_Message(FILE * f, char mesgid, const char *field[], int nfields)
{
	char            buf[256];
	int             i, len;

	len = snprintf(buf, sizeof(buf), "0%c", mesgid);

	for (i = 0; i < nfields; i++)
		len += snprintf(buf + len, sizeof(buf) - len, (i == 0) ? "%s" : "\001%s",
				field[i]);

	buf[0] = len;
	buf[len] = '\0';

	DPRINTF(">");
	DUMP_DATA(buf, len + 1);
	DUMP_PACKET(buf, len + 1);
	write_server(f, buf, len + 1);
	flush_server(f);
}

void
Send_Login(FILE * f, const char *login, const char *nick,
	   const char *group, const char *command,
	   const char *passwd, const char *status,
	   const char *level)
{
	const char     *fields[] = {login ? login : "",
		nick ? nick : "",
		group ? group : "",
		command ? command : "",
		passwd ? passwd : "",
		status ? status : "",
	level ? level : ""};

	Send_Message(f, M_LOGIN, fields,
		     5 + (status != NULL) + (level != NULL));
}

void
Send_Pong(FILE * f, const char *MesgID)
{
	const char     *fields[] = {(MesgID) ? MesgID : ""};
	Send_Message(f, M_PONG, fields, 1);
}

void
Send_Ping(FILE * f, const char *MesgID)
{
	const char     *fields[] = {(MesgID) ? MesgID : ""};
	Send_Message(f, M_PING, fields, 1);
}

void
Send_Command(FILE * f, const char *Command, const char *Message)
{
	const char     *fields[] = {Command, Message};
	Send_Message(f, M_COMMAND, fields, 2);
}

void
Send_NickCommand(FILE * f, const char *Command, const char *Nick,
		 const char *Message)
{
	char            buf[256];
	const char     *fields[] = {Command, buf};
	int             len = snprintf(buf, sizeof(buf), "%s %s", Nick, Message);
	buf[len] = '\0';
	Send_Message(f, M_COMMAND, fields, 2);
}

void
Pass(FILE * f, const char *User)
{
	Send_Command(f, "pass", User);
}

void
Group_Message(FILE * f, const char *Message)
{
	const char     *fields[] = {Message};
	Send_Message(f, M_OPEN, fields, 1);
}

void
Personal_Message(FILE * f, const char *Nick, const char *Message)
{
	Send_NickCommand(f, "m", Nick, Message);
}

void
Talk_Self(FILE * f, const char *Message)
{
	Personal_Message(f, nickname, Message);
}

int
parse_fields(char *buf, int *len, char *cmd, char *fields[], int max)
{
	int             ret = 0;
	int             i = 0;
	char           *p = buf;

	*len = *p++;
	*cmd = *p++;
	buf[*len] = '\0';

	if (*p != '\0') {
		while (i < max) {
			fields[i++] = p;
			p = strchr(p, 1);
			if (!p)
				break;

			*p++ = '\0';
		}
	}
	ret = i;
	while (i < max)
		fields[i++] = NULL;

	return ret;
}

void
bad_message()
{
	DPRINTF("malformed message\n");
	fprintf(output, "Malformed message\n");
}

void
print_time(const char *format)
{
	char            buf[BUFSIZE];
	strftime(buf, sizeof(buf), format, the_tm);
	fprintf(output, "%s", buf);
}

int
host_lookup(struct sockaddr_in * sock, const char *host)
{
	struct hostent *hp;

	if (inet_aton(host, &sock->sin_addr) != 0)
		strlcpy(hostname, host, sizeof(hostname));
	else {
		hp = gethostbyname(host);
		if (!hp)
			return 0;
		sock->sin_family = hp->h_addrtype;
		memcpy(&sock->sin_addr, hp->h_addr, hp->h_length);
		(void) strlcpy(hostname, hp->h_name, sizeof(hostname));
	}

	return 1;
}

int
server_connect(FILE ** f, struct sockaddr_in * srvaddr)
{
	int             fd;

	DPRINTF("server_connect\n");

	if (!f)
		fatal("Invalid memory address\n");

	if (*f) {
		DPRINTF("server_connect: closing old file\n");
		fclose(*f);
	}
	/* Open Socket */
	for (;;) {
		char            buf[64];
		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0)
			fatal("Invalid socket\n");

		DPRINTF("server_connect: trying to connect\n");

		if (connect(fd, (struct sockaddr *) srvaddr,
			    sizeof(struct sockaddr_in)) == 0)
			break;

		strerror_r(errno, buf, sizeof buf);
		get_the_time();
		print_time("[%k:%M] ");
		fprintf(output, "Failed to connect to server: %s\n", buf);
		fflush(output);

		close(fd);

		sleep(60);
		DPRINTF("server_connect: trying to connect again\n");
	}

	DPRINTF("server_connect: connected\n");

	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		char            buf[64];
		strerror_r(errno, buf, sizeof buf);
		fatal("Unable to set non-blocking IO: %s", buf);
	}
	*f = fdopen(fd, "r+");

	if (*f == NULL) {
		close(fd);
		fatal("fdopen\n");
	}
	if (setvbuf(*f, NULL, _IOFBF, 0)) {
		fclose(*f);
		fatal("setvbuf");
	}
	return fd;
}

extern char    *optarg;
extern int      optind;

int
main(int argc, char *argv[])
{
	struct sockaddr_in srvaddr;
	char            sock_buf[BUFSIZE];
	int             ret, c;

	sigemptyset(&sigset_alrm);
	sigaddset(&sigset_alrm, SIGALRM);

	signal(SIGALRM, alarm_handler);

	progname = argv[0];

	while ((c = getopt(argc, argv, "DGLd:f:g:n:p:u:m:")) != -1) {
		switch (c) {
		case 'D':	/* debug */
			nofork = 1;
			break;

		case 'G':	/* gmt */
			isgmt = 1;
			break;

		case 'd':	/* dir */
			isdir = 1;
			filename = optarg;
			break;

		case 'f':	/* file */
			isfile = 1;
			filename = optarg;
			break;

		case 'g':	/* group */
			group = optarg;
			break;

		case 'n':	/* nickname */
			nickname = optarg;
			break;

		case 'p':	/* port */
			port = atoi(optarg);
			break;

		case 't':	/* truncate */
			istrunc = 1;
			break;

		case 'u':	/* username */
			username = optarg;
			break;

		case 'm':
		  mailaddress = optarg;
		  break;

		default:
			usage();
			break;
		}
	}

	if (argc - optind <= 0)
		usage();

	if (!host_lookup(&srvaddr, argv[optind]))
		fatal("Host not found\n");

	if (isdir && isfile)
		usage();

	timefunc = (isgmt) ? gmtime : localtime;
	srvaddr.sin_port = htons(port);
	if (!filename && isdir)
		usage();

	if (isfile && filename)
		file_open(filename);
	else if (isdir && filename) {
		struct stat     s;

		if (stat(filename, &s)) {
			strerror_r(errno, sock_buf, sizeof sock_buf);
			fatal("Directory '%s' not found: %s\n", filename, sock_buf);
		}
		get_the_time();
		dir_time_open(filename);
	} else if (!nofork)
		fatal("not doing any logging, and running as a daemon!\n");

	/* Go into background */
	if (!nofork) {
		if (daemon(1, 0))
			fatal("Daemon failed\n");
	}
	for (;;) {
		int null_count = 0;

		server_connect(&server, &srvaddr);

		get_the_time();
		print_time("[%k:%M] ");
		fprintf(output, "Connected to server\n");
		fflush(output);
		DPRINTF("Connected\n");

		for (;;) {
			ret = read_packet(server, sock_buf, sizeof sock_buf);
			if (ret == -1)
				break;

			if (ret >= 2) {
				null_count = 0;
				process_packet(server, sock_buf, ret);
			} else {
				printf("null packet (%d)\n", ret);
				if (++null_count >= 10) {
					printf("too much confusion, "
					       "restarting\n");
					break;
				}
			}

		}

		alarm(0);
		sound_alarm = 0;

		get_the_time();
		print_time("[%k:%M] ");
		fprintf(output, "Lost connection to server\n");
		fflush(output);

		DPRINTF("Restarting server in 5 seconds\n");
		sleep(5);
	}
}

int
select_server(FILE * f, int iswrite, int dosigs)
{
	fd_set          fset;
	fd_set          eset;
	int             ret;
	int             fd;

	DPRINTF("select_server(%p, %d, %d)\n", f, iswrite, dosigs);

	if (errno && EAGAIN != errno && EINTR != errno)
		return (-1);

	fd = fileno(f);

	FD_ZERO(&fset);
	FD_SET(fd, &fset);

	FD_ZERO(&eset);
	FD_SET(fd, &eset);

	for (;;) {
		char            buf[64];

		errno = 0;
		ret = select(fd + 1, iswrite ? NULL : &fset,
			     iswrite ? &fset : NULL, &eset, NULL);

		if (ret > 0) {
			if (FD_ISSET(fd, &eset))
				return (-1);
			if (FD_ISSET(fd, &fset))
				return (0);
			return (-1);	/* ??? */
		}
		if (-1 == ret && EINTR == errno) {
			if (dosigs && !iswrite && sound_alarm)
				handle_signals(f);
			continue;
		}
		strerror_r(errno, buf, sizeof buf);
		DPRINTF("unknown error (ret = %d): %s\n", ret, buf);
		return (-1);
	}
}

int
flush_server(FILE * f)
{
	while (fflush(f)) {
		if (select_server(f, 1, 0))
			return (-1);
	}
	return (0);
}

int
write_server(FILE * f, const void *buf, size_t len)
{
	size_t          s;
	size_t          count = 0;

	for (count = 0; len > 0; count += s, buf += s, len -= s) {
		s = fwrite(buf, 1, len, f);

		DPRINTF("fwrite() = %d\n", s);

		if (0 == s) {
			if (select_server(f, 1, 0))
				return (-1);

			clearerr(f);
		}
	}

	return (count);
}

int
read_server(FILE * f, void *buf, size_t len, int dosigs)
{
	size_t          ret;

	for (;;) {
		ret = fread(buf, sizeof(char), len, f);

		DPRINTF("fread() = %d\n", ret);

		if (ret > 0)
			return (ret);

		if (feof(f))
			return (-1);

		if (errno == EAGAIN && dosigs) {
			if (sound_alarm) {
				handle_signals(f);
				continue;
			}
		}
		if (select_server(f, 0, dosigs))
			return (-1);
	}
}

void
handle_signals(FILE * f)
{
	char            buf[128];
	char            buf1[FILENAME_MAX + 1];

	if (!sound_alarm)
		return;

	sound_alarm = 0;
	DPRINTF("handle alarm\n");
	get_the_time();
	if (isdir && the_tm->tm_mday != the_last_day) {
	  if (the_last_year != 0) {
	    snprintf(buf1, sizeof(buf1), "/usr/bin/mail -s icblog %s < %s/%04d-%02d-%02d",
		     mailaddress, filename, the_last_year + 1900, the_last_month + 1, the_last_day);
	    system(buf1);
	  }
		dir_time_open(filename);
	}

	strftime(buf, sizeof(buf), (the_last_day != the_tm->tm_mday) ?
		 "Today is %a %b %e %Y %T %Z (%z)" : "Pinging Self (%R %Z)",
		 the_tm);
	Talk_Self(f, buf);

	the_last_day = the_tm->tm_mday;
	the_last_month = the_tm->tm_mon;
	the_last_year = the_tm->tm_year;

	new_alarm();
}

int
read_packet(FILE * f, void *buf, size_t len)
{
	int             ret;
	int             count = 0;
	int             pkt_len;
	int		extended;

	if (len < 256)
		fatal("packet size too small (%d)", len);

	/* Read the packet length(1 byte) */
	ret = read_server(f, buf, 1, 1);
	if (1 != ret)
		return (-1);

	pkt_len = *(unsigned char *) buf;

	/* Handle extended packets */
	extended = (pkt_len == 0);
	if (extended)
		pkt_len = 255;

	DPRINTF("reading %d (of %d) byte packet...", pkt_len, len);

	++count;
	--len;
	++buf;

	/* The packet length does * not * count the length byte. */
	while (count < pkt_len) {
		if (len < pkt_len - count + 1)
			fatal("packet processing error");
		ret = read_server(f, buf, pkt_len - count + 1, 0);
		if (ret == -1) {
			DPRINTF("failed\n");
			return (-1);
		}
		count += ret;
		len -= ret;
		buf += ret;
	}

	while (extended) {
		char dummy[256];
		char *p = dummy;

		/* Read the packet length(1 byte) */
		ret = read_server(f, p, 1, 1);
		if (1 != ret)
			return (-1);

		pkt_len = *(unsigned char *) p;

		/* Handle extended packets */
		extended = (pkt_len == 0);
		if (extended)
			pkt_len = 255;

		++count;
		--len;
		++p;

		/* The packet length does * not * count the length byte. */
		while (count < pkt_len) {
			if (len < pkt_len - count + 1)
				fatal("packet processing error");
			ret = read_server(f, p, pkt_len - count + 1, 0);
			if (ret == -1) {
				DPRINTF("failed\n");
				return (-1);
			}
			count += ret;
			len -= ret;
			p += ret;
		}
	}

	DPRINTF("read %d bytes\n", count);
	return (count);
}

#ifdef DEBUG
void
dump_packet(const void *buf, size_t len)
{
	const struct icb_packet *icb = buf;
	int             i;
	int             count = 0;
	const char     *p, *start;

	if (icb->length < 3 || icb->length + 1 > len) {
		fprintf(stderr, "malformed packet (len = %d, length = %d)\n", len, icb->length);
	}
	fprintf(stderr, "%d:%c/%02x ", icb->length,
	      (isprint(icb->type) && !iscntrl(icb->type)) ? icb->type : '.',
		icb->type);

	for (i = 0, p = icb->data, start = icb->data; i < icb->length; ++i, ++p) {
		if (1 == *p || '\0' == *p) {
			fprintf(stderr, "'");
			fwrite(start, 1, p - start, stderr);
			fprintf(stderr, "' ");
			if (++count >= MAX_FIELDS || '\0' == *p)
				break;
			start = p + 1;
		} else if (!isprint(*p) || iscntrl(*p)) {
			fprintf(stderr, "wacky char: %02x\n", *p);
		}
	}

	fprintf(stderr, "(%d fields)\n", count);
}

void
dump_data(const void *buf, size_t len)
{
    int c, i, j;
    const char *data = buf;
    
    for (i = 0; i < len; i += 16) {
	fprintf(stderr, "%08x  ", i);
	c = len - i;
	if (c > 16) c = 16;
	
	for (j = 0; j < c; j++) {
	    fprintf(stderr, "%02x ", data[i + j] & 0xff);
	    if ((j & 0xf) == 7 && j > 0)
		fprintf(stderr, " ");
	}
	
	for (; j < 16; j++)
	    fprintf(stderr, "   ");
	fprintf(stderr, "  ");
	
	for (j = 0; j < c; j++) {
	    int ch = data[i + j] & 0x7f;
	    fprintf(stderr, "%c", (char)(isprint(ch) ? ch : ' '));
	}
		
	fprintf(stderr, "\n");
	
	if (c < 16)
	    break;
    }
}
#endif				/* DEBUG */

int
process_packet(FILE * f, void *buf, size_t len)
{
	const char     *field[MAX_FIELDS];
	struct icb_packet *icb = buf;
	char           *p;
	int             i;
	int             count = 0;
	char            tmp[BUFSIZE];

	if (icb->length < 3 || icb->length + 1 > len)
		return (-1);

	if ('\0' != icb->data[icb->length - 1])
		icb->data[icb->length] = '\0';

	DPRINTF("<");
	DUMP_DATA(buf, len);
	DUMP_PACKET(buf, len);

	field[0] = icb->data;
	for (i = 0, p = icb->data; i < icb->length; ++i, ++p) {
		if ('\0' == *p) {
			++count;
			break;
		}
		if (1 == *p) {
			*p = '\0';
			if (++count >= MAX_FIELDS)
				break;
			field[count] = p + 1;
		} else if (!isprint(*p) || iscntrl(*p)) {
			DPRINTF("wacky char: %02x\n", *p);
#if 0
			*p = '.';
#endif
		}
	}

	DPRINTF("count = %d\n", count);

	get_the_time();
	print_time("[%k:%M] ");
	switch (icb->type) {
	case M_LOGINOK:
		fprintf(output, "login accepted\n");
		strftime(tmp, sizeof(tmp), "Today is %a %b %e %T %Z %Y", the_tm);
		Talk_Self(f, tmp);
		break;
	case M_OPEN:
		if (count != 2) {
			bad_message();
			break;
		}
		fprintf(output, "<%s> %s\n", field[0], field[1]);
		break;
	case M_PERSONAL:
		if (count != 2) {
			bad_message();
			break;
		}
		if (strncasecmp(nickname, field[0], sizeof(nickname)) == 0) {
			fprintf(output, "%s\n", field[1]);
			break;
		} else {
			char           *data;
			fprintf(output, "*%s* %s\n", field[0], field[1]);

			data = strchr(field[1], ' ');
			if (data) {
				*data++ = '\0';
#ifdef ICBLOG_CAN_TALK
				if (field[1] && strcasecmp("msg", field[1]) == 0) {
					field[2] = data;
					data = strchr(data, ' ');
					if (data)
						*data++ = '\0';
					if (field[2]) {
						Personal_Message(f, field[2], data ? data : "");
						break;
					}
				} else if (field[1] && strcasecmp("grp", field[1]) == 0) {
					Group_Message(f, data);
					break;
				} else
#endif
				if (field[1] && strcasecmp("pass", field[1]) == 0) {
					Pass(f, data);
					break;
				}
			}
		}

		Personal_Message(f, field[0], "I don't talk to strangers.");
		break;
	case M_STATUS:
		if (count != 2) {
			bad_message();
			break;
		}
		fprintf(output, "[=%s=] %s\n", field[0], field[1]);
		break;
	case M_ERROR:
		if (count != 1) {
			bad_message();
			break;
		}
		fprintf(output, "[=Error=] %s\n", field[0]);
		break;
	case M_IMPORTANT:
		if (count != 2) {
			bad_message();
			break;
		}
		fprintf(output, "[*%s*] %s\n", field[0], field[1]);
		break;
	case M_EXIT:
		fprintf(output, "Server initiated exit\n");
		exit(2);
		break;
	case M_CMDOUT:
		fprintf(output, "[=Command=] ");
		for (i = 0; i < count; ++i)
			fprintf(output, "'%s' ", field[i]);
		fprintf(output, "\n");
		break;
	case M_PROTO:
		Send_Login(f, username, nickname, group, "login", NULL,
			   NULL, NULL);
		get_the_time();
		sound_alarm = 1;
		handle_signals(f);
		fprintf(output, "login sent\n");
		break;
	case M_BEEP:
		if (count != 1) {
			bad_message();
			break;
		}
		fprintf(output, "[=Beep!=] %s\n", field[0]);
		break;
	case M_PING:
		if (count > 1) {
			bad_message();
			break;
		}
		fprintf(output, "[=Ping=]: %s\n", (count == 1) ? field[0] : "");
		Send_Pong(f, field[0]);
		fprintf(output, "<Pong>: %s\n", (count == 1) ? field[0] : "");
		break;
	case M_PONG:
		if (count > 1) {
			bad_message();
			break;
		}
		fprintf(output, "[=Pong=]: %s\n", (count == 1) ? field[0] : "");
		break;
	default:
		fprintf(output,
		    "unknown packet. Length = %d, Type = %c, Fields = %d: ",
			icb->length, icb->type, count);
		for (i = 0; i < count; ++i)
			fprintf(output, "'%s' ", field[i]);
		fprintf(output, "\n");
	}

	fflush(output);

	return 0;
}
