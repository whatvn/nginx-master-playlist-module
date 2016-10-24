# nginx-master-playlist-module

this thing only works in special environment, so it's not written to work the way you want
it can generate akamai token as query string to access protected location by akamai enabled token

# Example


```
 location /master {
                alias /data/stream;
                vod_master_playlist;
                vod_location hlsstreaming;
                vod_host localhost;
        }
```

then to request master playlist, do this:

```
$ curl "http:/localhost/test3.m3u8"
```

result:

```
	#EXTM3U
	#EXT-X-STREAM-INF:PROGRAM-ID=1,BANDWIDTH=1560000,RESOLUTION=640x360,CODECS="mp4a.40.2, avc1.4d4015"
	http://localhost/hlsstreaming/test_360.mp4/index.m3u8
	#EXT-X-STREAM-INF:PROGRAM-ID=1,BANDWIDTH=3120000,RESOLUTION=854x480,CODECS="mp4a.40.2, avc1.4d4015"
	http://localhost/hlsstreaming/test_480.mp4/index.m3u8
	#EXT-X-STREAM-INF:PROGRAM-ID=1,BANDWIDTH=5120000,RESOLUTION=1280x720,CODECS="mp4a.40.2, avc1.4d4015"
	http://localhost/hlsstreaming/test.mp4/index.m3u8	
```

# Directive


`vod_master_playlist` : enable this module

`vod_location` : location where you configure your vod in nginx

`vod_host`: your domain name

`playlist_type`: hls, dash, mss, hds, default is hls  *and it supports hls and dash by now*

`vod_akamai_token`: enable akamai token insertion. with this directive, this module will generate akamai token query strings and forward to location with akamai token enabled, to access protected content.

`vod_akamai_token_key`: secret key (in hex)

`vod_akamai_token_param_name`: default __hdna__

`vod_akamai_token_window`: expire time of generated token (default 86400)

`vod_akamai_token_acl`: akamai token acl, default `baseuri`



