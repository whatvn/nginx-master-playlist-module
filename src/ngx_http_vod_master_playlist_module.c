#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

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
} vod_playlist_t;



static ngx_command_t ngx_http_vod_master_playlist_commands[] = {
    { ngx_string("vod_master_playlist"),
        NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
        ngx_http_vod_playlist,
        0,
        0,
        NULL},
    { ngx_string("playlist_type"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        &ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(vod_playlist_t, playlist_type),
        NULL},
    { ngx_string("vod_location"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        &ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(vod_playlist_t, vod_location),
        NULL},
    { ngx_string("vod_host"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        &ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(vod_playlist_t, vod_host),
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
    return conf;
}

static char *ngx_http_vod_master_playlist_merge_conf(ngx_conf_t *cf, void *parent, void *child) {
    vod_playlist_t *prev = parent;
    vod_playlist_t *conf = child;

    ngx_conf_merge_str_value(conf->vod_location, prev->vod_location, "vod");
    ngx_conf_merge_str_value(conf->playlist_type, prev->playlist_type, "hls");
    ngx_conf_merge_str_value(conf->vod_host, prev->vod_host, "localhost");
    return NGX_CONF_OK;
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

void replace(char * o_string, char * s_string, char * r_string) {
    char buffer[100];
    char * ch;
    if (!(ch = strstr(o_string, s_string)))
        return;
    strncpy(buffer, o_string, ch - o_string);
    buffer[ch - o_string] = 0;
    sprintf(buffer + (ch - o_string), "%s%s", r_string, ch + strlen(s_string));
    o_string[0] = 0;
    strcpy(o_string, buffer);
    return replace(o_string, s_string, r_string);
}

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
    strcpy(ext, ".mp4");
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
    u_char *p = buffer;
    char mapped_path[200] = ""; // is it too much, but I dont want to use malloc() here
    ngx_memset(mapped_path, '\0', sizeof (char)*200); /* set all to 0 */
    strncpy(mapped_path, (char *) path.data, path.len - 4);
    replace(mapped_path, (char *) clcf->root.data, "");
    p = ngx_sprintf(p, "/%s%s,.mp4,", (const char *) conf->vod_location.data, mapped_path);
    for (i = 0; i < 3; i++) {
        if (ngx_http_vod_playlist_check_file_exist(path, (char *) resolution[i]) == NGX_OK) {
            p = ngx_sprintf(p, "_%s.mp4,", resolution[i]);
        }
    }
    if (ngx_memcmp(conf->playlist_type.data, DASH, conf->playlist_type.len) == 0) {
        p = ngx_sprintf(p, ".urlset/manifest.mpd\0");

    } else if (ngx_memcmp(conf->playlist_type.data, HLS, conf->playlist_type.len) == 0) {
        p = ngx_sprintf(p, ".urlset/master.m3u8\0");
    } else if (ngx_memcmp(conf->playlist_type.data, HDS, conf->playlist_type.len) == 0) {
        p = ngx_sprintf(p, ".urlset/manifest.f4m\0");
    } else if (ngx_memcmp(conf->playlist_type.data, MSS, conf->playlist_type.len) == 0) {
        p = ngx_sprintf(p, ".urlset/manifest\0");
    } else {
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }
    ngx_str_t location;
    location.data = buffer;
    location.len = ngx_strlen(buffer);
    ngx_http_internal_redirect(r, &location, &r->args);

    return NGX_HTTP_OK;
}

static char *ngx_http_vod_playlist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf =
            ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_master_playlist_handler;
    return NGX_CONF_OK;
}


