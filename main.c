/*
 * Copyright (c) 2010, 2011 Sergey Urbanovich
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <err.h>
#include <sysexits.h>
#include <netinet/in.h>
#include <strings.h>
#include <security/pam_appl.h>
#define EV_COMPAT3 0		/* Use the ev 4.X API. */
#include <ev.h>
#include "asn1/LDAPMessage.h"

#define LISTENQ 128

#define fail(msg) do { perror(msg); return; } while (0);
#define fail1(msg, ret) do { perror(msg); return ret; } while (0);
#define XNEW(type, n) ({void *_p=malloc(n*sizeof(type)); if (!_p) err(EX_OSERR, "malloc"); _p;})
#define XNEW0(type, n) ({void *_p=calloc(n,sizeof(type)); if (!_p) err(EX_OSERR, "calloc"); _p;})
#define XSTRDUP(s) ({char *_s=strdup(s); if (!_s) err(EX_OSERR, "strdup"); _s;})
#define XSTRNDUP(s, n) ({char *_s=strndup(s,n); if (!_s) err(EX_OSERR, "strndup"); _s;})
#define ldapmessage_free(msg) ASN_STRUCT_FREE(asn_DEF_LDAPMessage, msg)
#define ldapmessage_empty(msg) ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_LDAPMessage, msg)

#ifdef DEBUG
#define LDAP_DEBUG(msg) asn_fprint(stdout, &asn_DEF_LDAPMessage, msg)
#else
#define LDAP_DEBUG(msg)
#endif

#define BUFFER_SIZE 16384
typedef struct {
	char buf[BUFFER_SIZE];
	size_t len;
} buffer_t;
void buffer_init(buffer_t *buffer);
void buffer_appended(buffer_t *buffer, size_t len);
void buffer_consumed(buffer_t *buffer, size_t len);
#define buffer_wpos(buffer) ((buffer)->buf + (buffer)->len)
#define buffer_wlen(buffer) (BUFFER_SIZE - (buffer)->len)
#define buffer_rpos(buffer) ((buffer)->buf)
#define buffer_rlen(buffer) ((buffer)->len)
#define buffer_empty(buffer) (!(buffer)->len)

typedef struct {
	char *basedn;
	int anonymous;
	ev_loop *loop;
	ev_io connection_watcher;
} ldap_server;
void ldap_server_init(ldap_server *server, ev_loop *loop, char *basedn, int anonymous);
int ldap_server_start(ldap_server *server, uint32_t addr, int port);
void ldap_server_stop(ldap_server *server);
char *ldap_server_cn2name(ldap_server *server, const char *cn);

typedef struct {
	ldap_server *server;
	ev_io read_watcher;
	ev_io write_watcher;
	ev_timer delay_watcher;
	LDAPMessage_t *request;
	LDAPMessage_t *response;
	buffer_t recv_buf;
	buffer_t send_buf;
} ldap_connection;
ldap_connection *ldap_connection_new(ldap_server *server, int fd);
void ldap_connection_free(ldap_connection *connection);
void ldap_connection_send(ldap_connection *connection, LDAPMessage_t *msg);

void accept_cb(ev_loop *loop, ev_io *watcher, int revents);
void read_cb(ev_loop *loop, ev_io *watcher, int revents);
void write_cb(ev_loop *loop, ev_io *watcher, int revents);
void delay_cb(EV_P_ ev_timer *w, int revents);

void ldap_bind(int msgid, BindRequest_t *req, ev_loop *loop, ev_io *watcher);
void ldap_search(int msgid, SearchRequest_t *req, ev_loop *loop, ev_io *watcher);

typedef struct {
	const char *user, *pw;
	ev_tstamp delay;
} auth_pam_data_t;
int auth_pam(const char *user, const char *pw, char **msg, ev_tstamp *delay);
int auth_pam_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr);
void auth_pam_delay(int retval, unsigned usec_delay, void *appdata_ptr);

char *setting_basedn = "dc=entente";
int setting_port = 389;
int setting_daemon = 0;
int setting_loopback = 0;
int setting_anonymous = 0;
void settings(int argc, char **argv);

int main(int argc, char **argv)
{
	ev_loop *loop = EV_DEFAULT;
	ldap_server server;
	uint32_t server_addr;

	settings(argc, argv);
	server_addr = setting_loopback ? INADDR_LOOPBACK : INADDR_ANY;
	if (setting_daemon && daemon(0, 0))
		fail1("daemon", 1);
	ldap_server_init(&server, loop, setting_basedn, setting_anonymous);
	if (ldap_server_start(&server, server_addr, setting_port) < 0)
		fail1("ldap_server_start", 1);
	ev_run(loop, 0);
	return 0;
}

void buffer_init(buffer_t *buffer)
{
	buffer->len = 0;
}

void buffer_appended(buffer_t *buffer, size_t len)
{
	assert(len <= buffer_wlen(buffer));

	buffer->len += len;
}

void buffer_consumed(buffer_t *buffer, size_t len)
{
	assert(len <= buffer_rlen(buffer));

	buffer->len -= len;
	/* Shuffle any remaining data to start of buffer. */
	if (buffer->len) {
		memmove(buffer->buf, buffer->buf + len, buffer->len);
	}
}

void ldap_server_init(ldap_server *server, ev_loop *loop, char *basedn, int anonymous)
{
	server->basedn = basedn;
	server->anonymous = anonymous;
	server->loop = loop;
	ev_init(&server->connection_watcher, accept_cb);
	server->connection_watcher.data = server;
}

int ldap_server_start(ldap_server *server, uint32_t addr, int port)
{
	int serv_sd;
	int opt = 1;
	struct sockaddr_in servaddr;

	assert(!ev_is_active(&server->connection_watcher));

	if ((serv_sd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
		fail1("socket", -1);
	if (setsockopt(serv_sd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
		fail1("setsockopt", -1);
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(addr);
	servaddr.sin_port = htons(port);
	if (bind(serv_sd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
		fail1("bind", -1);
	if (listen(serv_sd, LISTENQ) < 0)
		fail1("listen", -1);
	ev_io_set(&server->connection_watcher, serv_sd, EV_READ);
	ev_io_start(server->loop, &server->connection_watcher);
	return serv_sd;
}

void ldap_server_stop(ldap_server *server)
{
	assert(ev_is_active(&server->connection_watcher));

	ev_io_stop(server->loop, &server->connection_watcher);
	close(server->connection_watcher.fd);
}

char *ldap_server_cn2name(ldap_server *server, const char *cn)
{
	/* cn=$username$,BASEDN => $username$ */
	char *pos = index(cn, ',');

	if (!pos || strncmp(cn, "cn=", 3) || strcmp(pos + 1, server->basedn))
		return NULL;
	return XSTRNDUP(cn + 3, pos - (cn + 3));
}

ldap_connection *ldap_connection_new(ldap_server *server, int fd)
{
	ldap_connection *connection = XNEW0(ldap_connection, 1);

	connection->server = server;
	ev_io_init(&connection->read_watcher, read_cb, fd, EV_READ);
	connection->read_watcher.data = connection;
	ev_io_init(&connection->write_watcher, write_cb, fd, EV_WRITE);
	connection->write_watcher.data = connection;
	ev_init(&connection->delay_watcher, NULL);
	connection->delay_watcher.data = connection;
	buffer_init(&connection->recv_buf);
	buffer_init(&connection->send_buf);
	ev_io_start(server->loop, &connection->read_watcher);
	return connection;
}

void ldap_connection_free(ldap_connection *connection)
{
	assert(ev_is_active(&connection->read_watcher));

	ev_io_stop(connection->server->loop, &connection->read_watcher);
	close(connection->read_watcher.fd);
	free(connection);
}

void ldap_connection_send(ldap_connection *connection, LDAPMessage_t *msg)
{
	buffer_t *buf = &connection->send_buf;
	asn_enc_rval_t rencode;

	LDAP_DEBUG(msg);
	rencode = der_encode_to_buffer(&asn_DEF_LDAPMessage, msg, buffer_wpos(buf), buffer_wlen(buf));
	buffer_appended(buf, rencode.encoded);
	ev_io_start(connection->server->loop, &connection->write_watcher);
}

void accept_cb(ev_loop *loop, ev_io *watcher, int revents)
{
	ldap_server *server = watcher->data;
	int client_sd;

	assert(server->loop == loop);
	assert(&server->connection_watcher == watcher);

	if (EV_ERROR & revents)
		fail("got invalid event");
	if ((client_sd = accept(watcher->fd, NULL, NULL)) < 0)
		fail("accept error");
	ldap_connection_new(server, client_sd);
}

void read_cb(ev_loop *loop, ev_io *watcher, int revents)
{
	ldap_connection *connection = watcher->data;
	buffer_t *buf = &connection->recv_buf;
	ssize_t buf_cnt;
	LDAPMessage_t *req = NULL;
	asn_dec_rval_t rdecode;

	assert(connection->server->loop == loop);
	assert(&connection->read_watcher == watcher);

	if (EV_ERROR & revents)
		fail("got invalid event");
	buf_cnt = recv(watcher->fd, buffer_wpos(buf), buffer_wlen(buf), 0);
	if (buf_cnt <= 0) {
		ldap_connection_free(connection);
		if (buf_cnt < 0)
			fail("read");
		return;
	}
	buffer_appended(buf, buf_cnt);
	/* from asn1c's FAQ: If you want data to be BER or DER encoded, just invoke der_encode(). */
	rdecode = ber_decode(0, &asn_DEF_LDAPMessage, (void **)&req, buffer_rpos(buf), buffer_rlen(buf));
	buffer_consumed(buf, rdecode.consumed);
	if (rdecode.code != RC_OK || (ssize_t) rdecode.consumed != buf_cnt) {
		ldap_connection_free(connection);
		ldapmessage_free(req);
		fail((rdecode.code != RC_OK) ? "der_decoder" : "consumed");
	}
	LDAP_DEBUG(req);
	switch (req->protocolOp.present) {
	case LDAPMessage__protocolOp_PR_bindRequest:
		ldap_bind(req->messageID, &req->protocolOp.choice.bindRequest, loop, watcher);
		break;
	case LDAPMessage__protocolOp_PR_searchRequest:
		ldap_search(req->messageID, &req->protocolOp.choice.searchRequest, loop, watcher);
		break;
	case LDAPMessage__protocolOp_PR_unbindRequest:
		ldap_connection_free(connection);
		break;
	default:
		perror("_|_");
		ldap_connection_free(connection);
	}
	ldapmessage_free(req);
}

void write_cb(ev_loop *loop, ev_io *watcher, int revents)
{
	ldap_connection *connection = watcher->data;
	buffer_t *buf = &connection->send_buf;
	ssize_t buf_cnt;

	assert(connection->server->loop == loop);
	assert(&connection->write_watcher == watcher);

	buf_cnt = send(watcher->fd, buffer_rpos(buf), buffer_rlen(buf), MSG_NOSIGNAL);
	if (buf_cnt < 0) {
		ldap_connection_free(connection);
		fail("send");
	}
	buffer_consumed(buf, buf_cnt);
	if (buffer_empty(buf))
		ev_io_stop(loop, watcher);
}

void delay_cb(ev_loop *loop, ev_timer *watcher, int revents)
{
	ldap_connection *connection = watcher->data;
	LDAPMessage_t *res = connection->response;

	assert(connection->server->loop == loop);
	assert(&connection->delay_watcher == watcher);

	ldap_connection_send(connection, res);
	ldapmessage_free(res);
	/* Restart the connection read_watcher after the delay. */
	ev_io_start(loop, &connection->read_watcher);
}

void ldap_bind(int msgid, BindRequest_t *req, ev_loop *loop, ev_io *watcher)
{
	ldap_connection *connection = watcher->data;
	ldap_server *server = connection->server;
	ev_tstamp delay = 0.0;
	LDAPMessage_t *res = XNEW0(LDAPMessage_t, 1);

	assert(server->loop == loop);
	assert(&connection->read_watcher == watcher);

	res->messageID = msgid;
	res->protocolOp.present = LDAPMessage__protocolOp_PR_bindResponse;
	BindResponse_t *bindResponse = &res->protocolOp.choice.bindResponse;
	OCTET_STRING_fromBuf(&bindResponse->matchedDN, (const char *)req->name.buf, req->name.size);

	if (server->anonymous && req->name.size == 0) {
		/* allow anonymous */
		asn_long2INTEGER(&bindResponse->resultCode, BindResponse__resultCode_success);
	} else if (req->authentication.present == AuthenticationChoice_PR_simple) {
		/* simple auth */
		char *user = ldap_server_cn2name(server, (const char *)req->name.buf);
		char *pw = (char *)req->authentication.choice.simple.buf;
		char *status = NULL;
		if (!user) {
			asn_long2INTEGER(&bindResponse->resultCode, BindResponse__resultCode_invalidDNSyntax);
		} else if (PAM_SUCCESS != auth_pam(user, pw, &status, &delay)) {
			asn_long2INTEGER(&bindResponse->resultCode, BindResponse__resultCode_invalidCredentials);
			OCTET_STRING_fromString(&bindResponse->diagnosticMessage, status);
		} else {	/* Success! */
			asn_long2INTEGER(&bindResponse->resultCode, BindResponse__resultCode_success);
		}
		free(user);
		free(status);
	} else {
		/* sasl or anonymous auth */
		asn_long2INTEGER(&bindResponse->resultCode, BindResponse__resultCode_authMethodNotSupported);
	}
	if (delay > 0.0) {
		connection->response = res;
		ev_timer_init(&connection->delay_watcher, delay_cb, delay, 0.0);
		connection->delay_watcher.data = connection;
		/* Stop the connection read_watcher to stop other requests while delayed. */
		ev_io_stop(loop, watcher);
		ev_timer_start(loop, &connection->delay_watcher);
	} else {
		ldap_connection_send(connection, res);
		ldapmessage_free(res);
	}
}

void ldap_search(int msgid, SearchRequest_t *req, ev_loop *loop, ev_io *watcher)
{
	ldap_connection *connection = watcher->data;
	ldap_server *server = connection->server;
	/* (user=$username$) => cn=$username$,BASEDN */
	char user[256];
	LDAPMessage_t *res = XNEW0(LDAPMessage_t, 1);

	assert(server->loop == loop);
	assert(&connection->read_watcher == watcher);

	AttributeValueAssertion_t *attr = &req->filter.choice.equalityMatch;
	int bad_dn = strcmp((const char *)req->baseObject.buf, server->basedn)
	    && strcmp((const char *)req->baseObject.buf, "");
	int bad_filter = req->filter.present != Filter_PR_equalityMatch
	    || strcmp((const char *)attr->attributeDesc.buf, "user");

	res->messageID = msgid;

	if (!bad_dn && !bad_filter) {
		/* result of search */
		res->protocolOp.present = LDAPMessage__protocolOp_PR_searchResEntry;
		SearchResultEntry_t *searchResEntry = &res->protocolOp.choice.searchResEntry;
		snprintf(user, sizeof(user), "cn=%s,%s", (const char *)attr->assertionValue.buf, server->basedn);
		OCTET_STRING_fromString(&searchResEntry->objectName, user);

		ldap_connection_send(connection, res);
		ldapmessage_empty(res);
	}

	/* search is done */
	res->protocolOp.present = LDAPMessage__protocolOp_PR_searchResDone;
	SearchResultDone_t *searchResDone = &res->protocolOp.choice.searchResDone;
	if (bad_dn) {
		asn_long2INTEGER(&searchResDone->resultCode, LDAPResult__resultCode_other);
		OCTET_STRING_fromString(&searchResDone->diagnosticMessage, "baseobject is invalid");
	} else if (bad_filter) {
		asn_long2INTEGER(&searchResDone->resultCode, LDAPResult__resultCode_other);
		OCTET_STRING_fromString(&searchResDone->diagnosticMessage, "filter not supported");
	} else {
		asn_long2INTEGER(&searchResDone->resultCode, LDAPResult__resultCode_success);
		OCTET_STRING_fromString(&searchResDone->matchedDN, server->basedn);
	}
	ldap_connection_send(connection, res);
	ldapmessage_free(res);
}

int auth_pam(const char *user, const char *pw, char **msg, ev_tstamp *delay)
{
	char status[256] = "";
	int pam_res = -1;
	auth_pam_data_t data;
	struct pam_conv conv_info;
	pam_handle_t *pamh = NULL;

	data.user = user;
	data.pw = pw;
	data.delay = 0.0;
	conv_info.conv = &auth_pam_conv;
	conv_info.appdata_ptr = (void *)&data;
	/* Start pam. */
	if (PAM_SUCCESS != (pam_res = pam_start("entente", user, &conv_info, &pamh))) {
		snprintf(status, sizeof(status), "PAM: Could not start pam service: %s\n", pam_strerror(pamh, pam_res));
	} else {
		/* Set failure delay handler function. */
		if (PAM_SUCCESS != (pam_res = pam_set_item(pamh, PAM_FAIL_DELAY, &auth_pam_delay)))
			snprintf(status, sizeof(status), "PAM: Could not set failure delay handler: %s\n",
				 pam_strerror(pamh, pam_res));
		/* Try auth. */
		else if (PAM_SUCCESS != (pam_res = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK)))
			snprintf(status, sizeof(status), "PAM: user %s - not authenticated: %s\n", user,
				 pam_strerror(pamh, pam_res));
		/* Check that the account is healthy. */
		else if (PAM_SUCCESS != (pam_res = pam_acct_mgmt(pamh, PAM_DISALLOW_NULL_AUTHTOK)))
			snprintf(status, sizeof(status), "PAM: user %s - invalid account: %s", user,
				 pam_strerror(pamh, pam_res));
		pam_end(pamh, PAM_SUCCESS);
	}
	*msg = XSTRDUP(status);
	*delay = data.delay;
	return pam_res;
}

int auth_pam_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
	int i;
	struct pam_response *res;
	auth_pam_data_t *data = (auth_pam_data_t *) appdata_ptr;

	if (!resp || !msg || !data)
		return PAM_CONV_ERR;
	res = XNEW0(struct pam_response, num_msg);
	for (i = 0; i < num_msg; i++) {
		/* select response based on requested output style */
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_ON:
			res[i].resp = XSTRDUP(data->user);
			break;
		case PAM_PROMPT_ECHO_OFF:
			res[i].resp = XSTRDUP(data->pw);
			break;
		default:
			free(res);
			return PAM_CONV_ERR;
		}
	}
	*resp = res;
	return PAM_SUCCESS;
}

void auth_pam_delay(int retval, unsigned usec_delay, void *appdata_ptr)
{
	auth_pam_data_t *data = (auth_pam_data_t *) appdata_ptr;

	/* Only set the delay if the auth failed. */
	if (PAM_SUCCESS != retval)
		data->delay = usec_delay * 1.0e-6;
}

void settings(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "ab:dlp:")) != -1) {
		switch (c) {
		case 'a':
			setting_anonymous = 1;
			break;
		case 'b':
			setting_basedn = optarg;
			break;
		case 'd':
			setting_daemon = 1;
			break;
		case 'l':
			setting_loopback = 1;
			break;
		case 'p':
			setting_port = atoi(optarg);
			break;
		default:
			fprintf(stderr, "Usage: %s [-a] [-b dc=entente] [-l] [-p 389] [-d]\n", argv[0]);
			exit(1);
		}
	}
}
