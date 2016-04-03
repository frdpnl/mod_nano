/*
 *  A nanomsg Apache 2.4 module.
 *
 *  Copyright 2016 frederic pinel (github: frdpnl)
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 * 
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>

#include "apr_hash.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "apr_hash.h"

#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include <nanomsg/nn.h>
#include <nanomsg/ipc.h>
#include <nanomsg/reqrep.h>

#define MOD_NN_ENDPOINT_LEN 256
#define MOD_NN_PRIORITY_DEFAULT 1
#define MOD_NN_NO_FD_YET -1
#define MOD_NN_ERR 128

static void register_hooks(apr_pool_t*);
static const char *nano_cmd_channel(cmd_parms*, void*, const char*, const char*);
static void *create_dir_conf(apr_pool_t*, char *);
static void *merge_dir_conf(apr_pool_t*, void*, void*);
static void nano_child_init(apr_pool_t*, server_rec*);
static apr_status_t nano_pool_exit(void*);
static int nano_handler(request_rec*);
static int nano_of_http(request_rec *, char **, size_t *);
static int nano_parse_rep(request_rec *, char *, apr_table_t **, char **);

/* Services table, per child. */
static apr_hash_t *Services = NULL;

typedef struct service_t_ {
	int soc;
	/* state can be expanded here */
	int nb_ep;
	int *end;
	char *ep;
} service_t;

/* Module configuration. */
typedef struct _nano_config_t {
	apr_array_header_t *channels;
} nano_config_t;

typedef struct channel_t_ {
	char endpoint[MOD_NN_ENDPOINT_LEN];
	int priority;
} channel_t;

static const command_rec nano_directives[] = 
{
	AP_INIT_TAKE12("nanoChannel",
		       nano_cmd_channel,
		       NULL,
		       ACCESS_CONF,
		       "Nanomsg endpoint, and optional priority, to request a reply from"),
	{NULL}
};

static service_t *nano_service(request_rec *, apr_hash_t **);
static service_t *nano_service_of_channels(apr_pool_t *, apr_hash_t **, apr_array_header_t *);
static int nano_interrogate(request_rec *, service_t *, apr_table_t **, char **, size_t *);

AP_DECLARE_MODULE(nano) =
{
	STANDARD20_MODULE_STUFF,
	create_dir_conf,	/* per-directory config handler */
	merge_dir_conf,		/* per-directory merge config handler */
	NULL,			/* create_svr_conf, per-server config handler */
	NULL,			/* merge_svr_conf */
	nano_directives,	/* directives, any directive we may have for httpd */
	register_hooks		/* our hook registering function */
};

static void register_hooks(apr_pool_t *pool)
{
	ap_hook_child_init(nano_child_init, NULL, NULL, APR_HOOK_LAST);
	ap_hook_handler(nano_handler, NULL, NULL, APR_HOOK_LAST);
}

static void *create_dir_conf(apr_pool_t *pool, char *context)
{
	nano_config_t *conf = (nano_config_t*) apr_pcalloc(pool, sizeof(nano_config_t));

	if (conf) {
		conf->channels = apr_array_make(pool, 1, sizeof(channel_t));
	}
	return conf;
}

static void *merge_dir_conf(apr_pool_t *pool, void *base_cfg, void *add_cfg)
{
	nano_config_t *base = (nano_config_t*) base_cfg;
	nano_config_t *add = (nano_config_t *) add_cfg;
	nano_config_t *conf = (nano_config_t *) create_dir_conf(pool, NULL);

	if (conf) {
		conf->channels = (add->channels ? add->channels : base->channels);
	}
	return conf;
}

const char *nano_cmd_channel(cmd_parms * cmd, void *cfg, const char *arg1, const char *arg2)
{
	apr_pool_t *pool = cmd->pool;
	int p;
	char *endptr;
	channel_t *ch;
	nano_config_t *conf = (nano_config_t *)cfg;

	if (conf) {
		ch = (channel_t*) apr_array_push(conf->channels);
		if (!ch) {
			return NULL;
		}
		apr_cpystrn(ch->endpoint, arg1, sizeof(ch->endpoint));
		/* The optional priority is defined */
		if (arg2) {
			errno = 0;
			p = strtol(arg2, &endptr, 10);
			if (errno != 0 || endptr == arg2) {
        			ap_log_error(APLOG_MARK, APLOG_ERR, APR_FROM_OS_ERROR(errno), cmd->server, APLOGNO(01000)
		                     "Incorrect priority, set a positive integer or omit, but not <%s>.", 
				     arg2);
				return "invalid endpoint priority set: expecting an integer.";
			} else {
				ch->priority = p;
			}
		} else {
			ch->priority = MOD_NN_PRIORITY_DEFAULT;
		}
	}
	return NULL;
}

static service_t *nano_service_of_channels(apr_pool_t *pool, apr_hash_t **rte, apr_array_header_t *chan)
{
	service_t *ret_val = NULL;
	/* Create the nano socket, and connect to endpoints. */
	int soc = nn_socket(AF_SP, NN_REQ);
	int *end = (int *)apr_palloc(pool, chan->nelts * sizeof(int));
	channel_t *ch;
	for (int i = 0; i < chan->nelts; ++i) {
		ch = &(APR_ARRAY_IDX(chan, i, channel_t));
		end[i] = nn_connect(soc, ch->endpoint);
	}
	/* Prepare the service record */
	ret_val = (service_t*)apr_palloc(pool, sizeof(service_t));
	ret_val->soc = soc;
	ret_val->nb_ep = chan->nelts;
	ret_val->end = end;
	return ret_val;
}

static apr_status_t nano_readbody(request_rec *req, char **bdy, apr_off_t *bdylen)
{
	apr_status_t status = APR_SUCCESS;
	int end = 0;
	apr_size_t bytes;
	const char *buf = NULL;
	apr_bucket *b = NULL;
	apr_bucket_brigade *bb = NULL;
	apr_array_header_t *ba;
	char *br;
	bb = apr_brigade_create(req->pool, req->connection->bucket_alloc);
	ba = apr_array_make(req->pool, 2, sizeof(br));
	apr_size_t count = 0;
	do {
		status = ap_get_brigade(req->input_filters, bb,
				AP_MODE_READBYTES, APR_BLOCK_READ, HUGE_STRING_LEN);
		if (status == APR_SUCCESS) {
			for (b = APR_BRIGADE_FIRST(bb);
					b != APR_BRIGADE_SENTINEL(bb);
					b = APR_BUCKET_NEXT(b)) {
				if (APR_BUCKET_IS_EOS(b)) {
					end = 1;
					break;
				}
				status = apr_bucket_read(b, &buf, &bytes, APR_BLOCK_READ);
				br = apr_pstrmemdup(req->pool, buf, bytes);
				*(const char **)apr_array_push(ba) = br;
				count += bytes;
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, req, APLOGNO(09000)
				     "Body bucket read: \"%s\" [strlen=%ld] [counted=%ld].", 
				     br, strlen(br), bytes);
			}
		}
		apr_brigade_cleanup(bb);
	} while (!end && status == APR_SUCCESS);
	if (status != APR_SUCCESS) {
		return status;
	}
	*bdy = apr_array_pstrcat(req->pool, ba, 0);
	*bdylen = count;
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, req, APLOGNO(09001)
	     "Body: \"%s\" [strlen=%ld] [counted=%ld].", *bdy, strlen(*bdy), *bdylen);
	apr_array_clear(ba);
	return APR_SUCCESS;
}

static int nano_of_http(request_rec *req, char **msg, size_t *msg_len)
{
	/* Return values: */
	int ret = OK;
	*msg = NULL;
	*msg_len = 0;

	/*----- process the header -----*/
	const apr_array_header_t *hdrs = apr_table_elts(req->headers_in);
	apr_table_entry_t *h = (apr_table_entry_t *) hdrs->elts;
	apr_size_t hdr_len = 0;
	for (int i=0; i < hdrs->nelts; i++) {
		/* Format: header_name: header_value\r\n". */
		hdr_len += strlen(h[i].key) + strlen(": ") + strlen(h[i].val) + strlen(CRLF);
	}
	hdr_len += strlen(CRLF);
	char *hdr = (char *)apr_pcalloc(req->pool, hdr_len +1); /* +1 for the terminating NULL. */
	char *hdr_cur = hdr;
	for (int i=0; i < hdrs->nelts; i++) {
		hdr_cur = apr_cpystrn(hdr_cur, h[i].key, strlen(h[i].key) +1);
		/* apr_cpystrn returns the pointer to the terminating NULL. */
		hdr_cur = apr_cpystrn(hdr_cur, ": ", strlen(": ") +1);
		hdr_cur = apr_cpystrn(hdr_cur, h[i].val, strlen(h[i].val) +1);
		hdr_cur = apr_cpystrn(hdr_cur, CRLF, strlen(CRLF) +1);
	}
	apr_cpystrn(hdr_cur, CRLF, strlen(CRLF) +1);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, req, APLOGNO(09002)
	     "Request header: \"%s\" [strlen=%ld] [counted=%ld].", 
	     hdr, strlen(hdr), hdr_len);
	/*----- process the boby -----*/
	char *bdy;
	apr_size_t bdy_len;
	if ((ret = nano_readbody(req, &bdy, &bdy_len)) != OK) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, ret, req, APLOGNO(01001)
		     "Reading body, error=%d.", ret);
		return ret;
	}
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, req, APLOGNO(09003)
	     "Request body: \"%s\"[strlen=%ld] [counted=%ld].", 
	     (bdy ? bdy : ""), (bdy ? strlen(bdy) : 0), bdy_len);
	*msg = apr_pstrcat(req->pool, req->the_request, CRLF, hdr, bdy, NULL);
	*msg_len = strlen(req->the_request) + strlen(CRLF) + hdr_len + bdy_len;
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, req, APLOGNO(09004)
	     "Request: \"%s\" [strlen=%ld] [counted=%ld].", 
	     *msg, strlen(*msg), *msg_len);
	return (OK);
}

static int nano_interrogate(request_rec *r, service_t *rte, apr_table_t **hdr, char **bdy, size_t *bdy_len)
{
	int ret = OK;
	char nn_strerror[MOD_NN_ERR], *p_nn_strerror;
	*bdy = NULL;
	*bdy_len = 0;
	*hdr = NULL;

	/*----- assemble the request message -----*/
	char *nn_req;
	size_t nn_req_len;
	if ((ret = nano_of_http(r, &nn_req, &nn_req_len))) {
		return (ret);
	}
	/*----- send the assembled message. -----*/
	errno = 0;
	size_t sent = nn_send(rte->soc, nn_req, nn_req_len, 0);
	int nn_errno = errno;
	if (sent != nn_req_len) {
		p_nn_strerror = strerror_r(nn_errno, nn_strerror, MOD_NN_ERR);
		ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_FROM_OS_ERROR(nn_errno), r, APLOGNO(01002)
		    "nn_send, error \"%s\", sent=%ld/%ld.", 
		     p_nn_strerror, sent, nn_req_len);
		return HTTP_SERVICE_UNAVAILABLE;
	}
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(09005)
	     "Sent: \"%s\" [len=%ld] [sent=%ld].", 
	     nn_req, nn_req_len, sent);
	/*----- receive a reply -----*/
	errno = 0;
	char *nn_rep;
	size_t recv = nn_recv(rte->soc, &nn_rep, NN_MSG, 0);
	nn_errno = errno;
	if (recv == -1) {
		p_nn_strerror = strerror_r(nn_errno, nn_strerror, MOD_NN_ERR);
		ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_FROM_OS_ERROR(errno), r, APLOGNO(01003)
		     "nn_recv, error=\"%s\".", p_nn_strerror);
		return HTTP_SERVICE_UNAVAILABLE;
	}
	char *rep = apr_pstrmemdup(r->pool, nn_rep, recv);
	errno = 0;
	if (nn_freemsg(nn_rep) != 0) {
		nn_errno = errno;
		p_nn_strerror = strerror_r(nn_errno, nn_strerror, MOD_NN_ERR);
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, APR_FROM_OS_ERROR(nn_errno), r, APLOGNO(01004)
		     "nn_freemsg, error=\"%s\".", p_nn_strerror);
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(09006)
	     "Reply: \"%s\" [strlen %ld] [recv %ld].", rep, strlen(rep), recv);
	ret = nano_parse_rep(r, rep, hdr, bdy);
	*bdy_len = strlen(*bdy);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(09007)
	     "Reply %3d, body: \"%s\" [len=%ld].", ret, *bdy, *bdy_len);
	return ret;
}

static int nano_parse_rep(request_rec *r, char *rep, apr_table_t **hdr, char **bdy)
{
	int code = HTTP_OK;
	char line[HUGE_STRING_LEN];
	size_t replen = strlen(rep);
	// line 0
	char *last = strcasestr(rep, CRLF);
	if (!last) {
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	size_t llen = last-rep;
       	if (llen == 0 || llen >= HUGE_STRING_LEN) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(01005)
		     "Status line invalid (%ld).", llen);
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	memcpy(line, rep, llen);
	line[llen] = 0;
	if (sscanf(line, "HTTP/1.1 %3d %*s", &code) != 1) {
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(09008)
	     "Status: <%s>", line);
	*hdr = apr_table_make(r->pool, 4);
	// line i
	char h[128], v[128];
	char *first = (last+(size_t)2) > (rep + replen) ? (rep + replen) : (last+(size_t)2);  // CR and LF
	while (last = strcasestr(first, CRLF)) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(09009)
		     "first=%ld, last=%ld", (size_t)first, (size_t)last);
		llen = last-first;
		if (llen >= HUGE_STRING_LEN) {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(01006)
		     	"Header line too long.");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		if (llen == 0) {
			last++; last++;
			*bdy = last;
			break;
		}
		memcpy(line, first, llen);
		line[llen] = 0;
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(09010)
		     "Line to scan: \"%s\".", line);
		if (sscanf(line, "%127[a-zA-Z0-9_-]: %127s", h, v) == 2) {
			apr_table_set(*hdr, h, v);
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(09011)
			     "Scanned header: \"%s\", value:\"%s\".", h, v);
		}
		first = (last+2) > (rep + replen) ? (rep + replen) : (last+2);
	}
	return code;
}

static service_t *nano_service(request_rec *req, apr_hash_t **rte)
{
	service_t *r_val = NULL; /* return value: service record */
	apr_pool_t *pp = req->server->process->pool;
	apr_pool_t *rp = req->pool;
	int soc, *end;
	nano_config_t *cfg = (nano_config_t*) ap_get_module_config(
			req->per_dir_config, &nano_module);
	if (apr_is_empty_array(cfg->channels)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, req, APLOGNO(01006)
		     "No endpoint configured for \"%s\".", req->uri);
		return NULL;
	}
	/* Create Services hash table if not created yet.  */
	if (!(*rte)) {
		*rte = apr_hash_make(pp);
	}
	/* Assemble the key: 
	 * concatenation of the configured endpoints for this request. */
	apr_size_t r_key_size = 1;
	channel_t *ch;
	for (int i = 0; i < cfg->channels->nelts; ++i) {
		ch = &(APR_ARRAY_IDX(cfg->channels, i, channel_t));
		r_key_size += strlen(ch->endpoint);
	}
	char *r_key = (char *)apr_palloc(pp, r_key_size);
	char *r_key_cur = r_key;
	for (int i = 0; i < cfg->channels->nelts; ++i) {
		ch = &(APR_ARRAY_IDX(cfg->channels, i, channel_t));
		r_key_cur = apr_cpystrn(r_key_cur, ch->endpoint, 1+strlen(ch->endpoint));
	}
	/* Do we have an existing service for this configuration? */
	if (r_val = (service_t*)apr_hash_get(*rte, r_key, APR_HASH_KEY_STRING)) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, req, APLOGNO(09012)
	     		"FOUND service {soc=%d, end=%d (total=%d), key=\"%s\"}.", 
			r_val->soc, r_val->end[0], r_val->nb_ep, r_val->ep);
		return r_val;
	}
	/* Can we create one? */
	if (r_val = nano_service_of_channels(pp, rte, cfg->channels)) {
		r_val->ep = r_key;  /* TODO temporary debug field to remove */
		apr_hash_set(*rte, r_key, APR_HASH_KEY_STRING, r_val);
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, req, APLOGNO(09013)
			"NEW service {soc=%d, end=%d (total=%d), key=\"%s\"}.", 
			r_val->soc, r_val->end[0], r_val->nb_ep, r_val->ep);
		return r_val;
	}
	return NULL;
}

static void nano_child_init(apr_pool_t *p, server_rec *svr)
{
	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, svr, APLOGNO(09014)
	     "Child_init: pid=<%d>.", getpid());
	/* Free nano resources (shutdown endpoint) */
	apr_pool_cleanup_register(p, svr, nano_pool_exit, apr_pool_cleanup_null);
}

static apr_status_t nano_pool_exit(void *data)
{
	server_rec *svr = data;
 	apr_hash_index_t *ri;
 	service_t *rte;
	int rc;
	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, svr, APLOGNO(09015)
	     "Pool exit: Services #<%#0lx>, pid=%d.", (unsigned long)Services, getpid());
	if (!Services) {
		return APR_SUCCESS;
	}
 	for (ri = apr_hash_first(NULL, Services); ri; ri = apr_hash_next(ri)) {
 		rte = (service_t*)apr_hash_this_val(ri);
		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, svr, APLOGNO(09016)
			"Pool exit: service {soc=%d, %d ends, key=\"%s\"}.", 
			rte->soc, rte->nb_ep, rte->ep);
		for (int i = 0; i < rte->nb_ep; i++) {
			if (rte->end[i] == -1)
				continue;
			rc = nn_shutdown(rte->soc, rte->end[i]);
			ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, svr, APLOGNO(09017)
	     			"Pool exit: %d=nn_shutdown(end=%d).", 
				rc, rte->end[i]);
			rte->end[i] = -1;
		}
		if (rte->soc != -1) {
			rc = nn_close(rte->soc);
			ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, svr, APLOGNO(09018)
				"Pool exit: %d=nn_closed(service {soc=%d, key=\"%s\"}).", 
				rc, rte->soc, rte->ep);
			rte->soc = -1;
		}
 	}
	return APR_SUCCESS;
}

static int setn_hdr_out(void *rec, const char *k, const char *v) {
	request_rec *r = (request_rec *)rec;
	apr_table_setn(r->headers_out, k, v);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(09019)
		"Set \"%s\": \"%s\".", k, v); 
	return 1;
}

static int nano_handler(request_rec *r)
{
	int ret = OK;
	if (!r->handler || strcmp(r->handler, "nano-handler")) {
		return DECLINED;
	}
	/* Get the microservice address (channels). */
	service_t *srv = nano_service(r, &Services);
	if (!srv) {
		return HTTP_NOT_FOUND;
	}
	/* Interrogate the microservice. */
	char *rep_bdy;
	size_t rep_len;
	apr_table_t *rep_hdr;
	ret = nano_interrogate(r, srv, &rep_hdr, &rep_bdy, &rep_len);
	if (!ap_is_HTTP_SUCCESS(ret)) {
		return ret;
	}
	/* If microservice successfully answered, set headers and body. */
	if (!apr_table_do(setn_hdr_out, (void *)r, rep_hdr, NULL)) {
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	ap_rputs(rep_bdy, r);
	return (OK);
}

