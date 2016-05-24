#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <malloc.h>

#define TOKEN_FORMAT "st=%uD~exp=%uD~acl=%V"
#define HMAC_PARAM "~hmac="


static const char* HLS = "hls";
static const char* DASH = "dash";
static const char* HDS = "hds";
static const char* MSS = "mss";



static const char *resolution[] = {
    "720",
    "480", "360"
};
static char *ngx_http_vod_playlist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_vod_master_playlist_create_location_conf(ngx_conf_t *cf);
static char *ngx_http_vod_master_playlist_merge_conf(ngx_conf_t *cf, void *parent, void *child);

typedef struct {
    ngx_str_t playlist_type;
    ngx_str_t vod_host;
    ngx_str_t vod_location;
    ngx_flag_t vod_akamai_token;
    ngx_str_t vod_akamai_token_param_name;
    ngx_uint_t vod_akamai_token_window;
    ngx_http_complex_value_t *vod_akamai_token_acl;
    ngx_str_t vod_akamai_token_key;
} vod_playlist_t;

static int
ngx_conf_get_hex_char_value(int ch) {
    if (ch >= '0' && ch <= '9') {
        return (ch - '0');
    }

    ch = (ch | 0x20); // lower case

    if (ch >= 'a' && ch <= 'f') {
        return (ch - 'a' + 10);
    }

    return -1;
}

static char *
ngx_conf_vod_set_hex_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *field;
	ngx_str_t *value;
    u_char *p;
	size_t i;
	int digit1;
	int digit2;

    field = (ngx_str_t *) ((u_char*)conf + cmd->offset);

    if (field->data) {
        return "is duplicate";
    }

    value = cf->args->elts;

	if (value[1].len & 0x1) {
		return "length is odd";
	}
	field->data = ngx_palloc(cf->pool, value[1].len >> 1);
	if (field->data == NULL) {
		return "alloc failed";
	}
	p = field->data;
	
	for (i = 0; i < value[1].len; i += 2)
	{
		digit1 = ngx_conf_get_hex_char_value(value[1].data[i]);
		digit2 = ngx_conf_get_hex_char_value(value[1].data[i + 1]);
		if (digit1 < 0 || digit2 < 0) {
			return "contains non hex chars";
		}
		*p++ = (digit1 << 4) | digit2;
	}
	field->len = p - field->data;

    return NGX_CONF_OK;
}


static ngx_command_t ngx_http_vod_master_playlist_commands[] = {
    { ngx_string("vod_master_playlist"),
        NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
        ngx_http_vod_playlist,
        0,
        0,
        NULL},
    { ngx_string("playlist_type"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(vod_playlist_t, playlist_type),
        NULL},
    { ngx_string("vod_location"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(vod_playlist_t, vod_location),
        NULL},
    { ngx_string("vod_host"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(vod_playlist_t, vod_host),
        NULL},
    { ngx_string("vod_akamai_token"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(vod_playlist_t, vod_akamai_token),
        NULL},
    { ngx_string("vod_akamai_token_key"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_vod_set_hex_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(vod_playlist_t, vod_akamai_token_key),
        NULL},
    { ngx_string("vod_akamai_token_param_name"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(vod_playlist_t, vod_akamai_token_param_name),
        NULL},
    { ngx_string("vod_akamai_token_window"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(vod_playlist_t, vod_akamai_token_window),
        NULL},
    { ngx_string("vod_akamai_token_acl"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_http_set_complex_value_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(vod_playlist_t, vod_akamai_token_acl),
        NULL},

    ngx_null_command
};

static ngx_http_module_t ngx_http_vod_master_playlist_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_vod_master_playlist_create_location_conf, /* create location configuration */
    ngx_http_vod_master_playlist_merge_conf /* merge location configuration */
};

ngx_module_t ngx_http_vod_master_playlist_module = {
    NGX_MODULE_V1,
    &ngx_http_vod_master_playlist_module_ctx, /* module context */
    ngx_http_vod_master_playlist_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *ngx_http_vod_master_playlist_create_location_conf(ngx_conf_t * cf) {
    vod_playlist_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof (vod_playlist_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->playlist_type.data = NULL;
    conf->playlist_type.len = 0;
    conf->vod_host.data = NULL;
    conf->vod_host.len = 0;
    conf->vod_location.data = NULL;
    conf->vod_location.len = 0;
    conf->vod_akamai_token = NGX_CONF_UNSET;
    conf->vod_akamai_token_key.data = NULL;
    conf->vod_akamai_token_key.len = 0;
    conf->vod_akamai_token_param_name.data = NULL;
    conf->vod_akamai_token_param_name.len = 0;
    conf->vod_akamai_token_window = NGX_CONF_UNSET_UINT;
    return conf;
}

static char *ngx_http_vod_master_playlist_merge_conf(ngx_conf_t *cf, void *parent, void *child) {
    vod_playlist_t *prev = parent;
    vod_playlist_t *conf = child;
    if (conf->vod_akamai_token_acl == NULL) {
        conf->vod_akamai_token_acl = prev->vod_akamai_token_acl;
    }
    ngx_conf_merge_str_value(conf->vod_location, prev->vod_location, "vod");
    ngx_conf_merge_str_value(conf->playlist_type, prev->playlist_type, "hls");
    ngx_conf_merge_str_value(conf->vod_host, prev->vod_host, "localhost");
    ngx_conf_merge_value(conf->vod_akamai_token, prev->vod_akamai_token, 0);
    ngx_conf_merge_str_value(conf->vod_akamai_token_key, prev->vod_akamai_token_key, "");
    ngx_conf_merge_str_value(conf->vod_akamai_token_param_name, prev->vod_akamai_token_param_name, "__hdnea__");
    ngx_conf_merge_uint_value(conf->vod_akamai_token_window, prev->vod_akamai_token_window, 86400);
    return NGX_CONF_OK;
}

static void *
ngx_http_secure_token_memrchr(const u_char *s, int c, size_t n) {
    const u_char *cp;

    for (cp = s + n; cp > s;) {
        if (*(--cp) == (u_char) c)
            return (void*) cp;
    }
    return NULL;
}

static ngx_int_t
ngx_http_secure_token_set_baseuri(ngx_str_t *uri, ngx_http_variable_value_t *v, uintptr_t data) {
    u_char* last_slash_pos;
    u_char* acl_end_pos;
    u_char* comma_pos;

    last_slash_pos = ngx_http_secure_token_memrchr(uri->data, '/', uri->len);
    if (last_slash_pos == NULL) {
        return NGX_ERROR;
    }

    acl_end_pos = last_slash_pos + 1;

    comma_pos = memchr(uri->data, ',', uri->len);
    if (comma_pos != NULL) {
        acl_end_pos = ngx_min(acl_end_pos, comma_pos);
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->len = acl_end_pos - uri->data;
    v->data = uri->data;

    return NGX_OK;
}

ngx_int_t
ngx_http_vod_get_akamai_acl(ngx_http_request_t *r, ngx_http_complex_value_t *acl_conf, ngx_str_t* acl, ngx_str_t* uri) {
    ngx_http_variable_value_t var_value;

    // get the acl
    if (acl_conf != NULL) {
        if (ngx_http_complex_value(r, acl_conf, acl) != NGX_OK) {
            return NGX_ERROR;
        }
    } else {
        // the default is 'baseuri'
        if (ngx_http_secure_token_set_baseuri(uri, &var_value, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        acl->data = var_value.data;
        acl->len = var_value.len;
    }

    return NGX_OK;
}

void strsncat(char *dest, size_t size, char * strs[], size_t n) {
    size--;
    char *p = dest;
    while (n-- > 0) {
        size_t len = strlen(*strs);
        if (len >= size) {
            len = size;
        }
        size -= len;
        memmove(p, *strs, len);
        strs++;
        p += len;
    }
    *p = '\0';
}

int ngx_http_vod_playlist_check_file_exist(ngx_str_t path,
        char *size) {
    char fullpath[200] = "";
    strncpy(fullpath, (char *) path.data, path.len - 4 * sizeof (char));
    char *strs[] = {fullpath, "_", size, ".mp4"};

    strsncat(fullpath, sizeof (fullpath), strs, sizeof (strs) / sizeof (strs[0]));
    if (access(fullpath, F_OK) != -1) {
        return NGX_OK;
    }
    return NGX_ERROR;
}

/*
void replace(char * o_string, char * s_string, char * r_string) {
    char buffer[100];
    char * ch;
    if (!(ch = strstr(o_string, s_string)))
        return;
    strncpy(buffer, o_string, ch - o_string);
    buffer[ch - o_string] = 0;
    sprintf(buffer + (ch - o_string), "%s%s", r_string, ch + strlen(s_string));
    o_string[0] = 0;
    strncpy(o_string, buffer, strlen(buffer));
    return replace(o_string, s_string, r_string);
}
*/

static ngx_int_t ngx_master_playlist_handler(ngx_http_request_t * r) {

    size_t root;
    ngx_int_t rc;
    ngx_uint_t level;
    ngx_str_t path;
    ngx_open_file_info_t of;
    ngx_http_core_loc_conf_t *clcf;
    unsigned int i;
    vod_playlist_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_vod_master_playlist_module);
    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)))
        return NGX_HTTP_NOT_ALLOWED;

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    if (!ngx_http_map_uri_to_path(r, &path, &root, 1)) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_t * nlog = r->connection->log;

    /* change file name to mp4
     * in order to lookup file in filesystem
     */

    char *ext = strrchr((const char *) path.data, '.');
    if (ext == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }
    /*
     * we have 2 options to implement this module
     * 1. Based on request extension by checking r->exten.data:
     *      - if m3u8 -> hls
     *      - if mpd  -> dash
     *      - if manifest -> hds
     *      - something else
     * 2. Use configuration directive to drive request to special function (this
     * option is more distinct
     * I choose option 2 by now, because most production environment just use one of these protocol
     */
    if (ngx_strncmp(ext, ".mpd", 4) != 0  && ngx_strncmp(ext, ".m3u8", 5) != 0 
            && ngx_strncmp(ext, ".manifest", 9) != 0 && ngx_strncmp(ext, ".f4m", 4) != 0 ) {
        return NGX_HTTP_NOT_ALLOWED;
    }
    strncpy(ext, ".mp4", 4);
    path.len = ((u_char *) ext - path.data) + 4;
    path.data[path.len] = '\0';
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    ngx_memzero(&of, sizeof (ngx_open_file_info_t));
    of.read_ahead = clcf->read_ahead;
    of.directio = NGX_MAX_OFF_T_VALUE;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;
    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool) != NGX_OK) {
        switch (of.err) {
            case 0:
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            case NGX_ENOENT:
            case NGX_ENOTDIR:
            case NGX_ENAMETOOLONG:
                level = NGX_LOG_ERR;
                rc = NGX_HTTP_NOT_FOUND;
                break;
            case NGX_EACCES:
                level = NGX_LOG_ERR;
                rc = NGX_HTTP_FORBIDDEN;
                break;
            default:
                level = NGX_LOG_CRIT;
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                break;
        }
        if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
            ngx_log_error(level, nlog, of.err,
                    ngx_open_file_n " \"%s\" failed", path.data);
        }

        return rc;
    }


    if (!of.is_file) {
        if (ngx_close_file(of.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, nlog, ngx_errno,
                    ngx_close_file_n " \"%s\" failed", path.data);
        }
        return NGX_DECLINED;
    }
    u_char *buffer = (u_char *) ngx_pcalloc(r->pool, 1024 * 256);
    u_char *tmp = buffer;
    char mapped_path[200] = ""; // is it too much, but I dont want to use malloc() here
    ngx_memset(mapped_path, '\0', sizeof (char)*200); /* set all to 0 */
    strncpy(mapped_path, (char *) path.data, path.len - 4);
    char* repl = mapped_path;
    while ((repl = strstr(repl, (char *) clcf->root.data)) != NULL) {
        char* t = repl;
        char* s = repl + clcf->root.len;
        while ((*t++ = *s++));
    }
    repl = NULL;
    if (strcmp((const char*) conf->vod_location.data, "/") > 0) {
        tmp = ngx_sprintf(tmp, "%s", (const char *) conf->vod_location.data);
    }
    tmp = ngx_sprintf(tmp, "%s,.mp4,", mapped_path);
    for (i = 0; i < 3; i++) {
        if (ngx_http_vod_playlist_check_file_exist(path, (char *) resolution[i]) == NGX_OK) {
            tmp = ngx_sprintf(tmp, "_%s.mp4,", resolution[i]);
        }
    }
    if (ngx_memcmp(conf->playlist_type.data, DASH, conf->playlist_type.len) == 0) {
        tmp = ngx_sprintf(tmp, ".urlset/manifest.mpd\0");
    } else if (ngx_memcmp(conf->playlist_type.data, HLS, conf->playlist_type.len) == 0) {
        tmp = ngx_sprintf(tmp, ".urlset/master.m3u8\0");
    } else if (ngx_memcmp(conf->playlist_type.data, HDS, conf->playlist_type.len) == 0) {
        tmp = ngx_sprintf(tmp, ".urlset/manifest.f4m\0");
    } else if (ngx_memcmp(conf->playlist_type.data, MSS, conf->playlist_type.len) == 0) {
        tmp = ngx_sprintf(tmp, ".urlset/manifest\0");
    } else {
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }
    ngx_str_t location;
    location.data = buffer;
    location.len = ngx_strlen(buffer);
    
    // now comes akamai token checking
    if (conf->vod_akamai_token) {
        time_t current_time = ngx_time();
        u_char hash[EVP_MAX_MD_SIZE];
        unsigned hash_len;
        HMAC_CTX hmac;
        ngx_str_t signed_part;
        size_t result_size;
        ngx_str_t result;
        result.data = NULL;
        result.len = 0;
        u_char* p = NULL;
        ngx_str_t acl;
        r->uri = location;
        rc = ngx_http_vod_get_akamai_acl(r, conf->vod_akamai_token_acl, &acl, &location);
        if (rc != NGX_OK) {
            return rc;
        }

        result_size = conf->vod_akamai_token_param_name.len + 1 + sizeof (TOKEN_FORMAT) + 2 * NGX_INT32_LEN + acl.len + sizeof (HMAC_PARAM) - 1 + EVP_MAX_MD_SIZE * 2 + 1;

        result.data = ngx_pnalloc(r->pool, result_size);
        if (result.data == NULL) {
            return NGX_ERROR;
        }
        p = ngx_copy(result.data, conf->vod_akamai_token_param_name.data, conf->vod_akamai_token_param_name.len);
        *p++ = '=';

        signed_part.data = p;
        p = ngx_sprintf(p, TOKEN_FORMAT, current_time, current_time + conf->vod_akamai_token_window, &acl);
        
        signed_part.len = p - signed_part.data;
        HMAC_CTX_init(&hmac);
        HMAC_Init(&hmac, conf->vod_akamai_token_key.data, conf->vod_akamai_token_key.len, EVP_sha256());
        HMAC_Update(&hmac, signed_part.data, signed_part.len);
        HMAC_Final(&hmac, hash, &hash_len);
        HMAC_CTX_cleanup(&hmac);

        p = ngx_copy(p, HMAC_PARAM, sizeof (HMAC_PARAM) - 1);
        p = ngx_hex_dump(p, hash, hash_len);

        result.len = p - result.data;
        /*
         *tmp++ = '?';
        tmp = ngx_copy(tmp, result.data, result.len);
        location.len = location.len + result.len + 1;
        tmp = ngx_copy(tmp, args.data, args.len);
        *tmp = '\0';
        ngx_log_error(NGX_LOG_ERR, nlog, 0,
                "akamai built token: %s\n", result.data);
        printf("Args: %s\n", (const char*) r->args.data);
        char *token;
        // duplicate r->args 
        char *qstrs = strdup((const char*) r->args.data);
        ngx_str_t args;
        args.data = r->args.data;
        args.len = r->args.len;
        token = strtok(qstrs, " ");
        while (token != NULL) {
            printf(" %s\n", token);

            token = strtok(NULL, " ");
        }
        printf("Args: %s\n", (const char*) qstrs);
        repl = (char *) args.data;
        while ((repl = strstr(repl, qstrs)) != NULL) {
            char* t = repl;
            args.len--;
            char* s = repl + ngx_strlen(qstrs);
            while ((*t++ = *s++));
        }
       
        printf("Args: %s\n", (const char*) args.data);
        
        if (qstrs) free(qstrs);
       
        
        printf("args len: %zu\t result len: %zu\t Location len: %zu\t, strlen: %zu ", location.len, ngx_strlen(location.data), result.len, args.len);
        p = ngx_copy(p, args.data, args.len);
        result.len += args.len + 1;
        *p = '\0';
        result.len += args.len + 1;
        printf("result len: %zu\t", result.len);
        *p = '\0';
        printf("final args: %s\n", (const char*) result.data);
        printf("final location: %s\n", (const char*) location.data);
        r->headers_out.location = ngx_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
        r->headers_out.location->hash = 1;
        r->headers_out.location->key.len = sizeof("Location") - 1;
        r->headers_out.location->key.data = (u_char *) "Location";
        r->headers_out.location->value.len = location.len;
        r->headers_out.location->value.data = location.data; 
        return NGX_HTTP_MOVED_TEMPORARILY; 
        
        */
        ngx_http_internal_redirect(r, &location, &result);
    } else {
        ngx_http_internal_redirect(r, &location, &r->args);
    }

    return NGX_HTTP_OK;
}

static char *ngx_http_vod_playlist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf =
            ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_master_playlist_handler;
    return NGX_CONF_OK;
}


