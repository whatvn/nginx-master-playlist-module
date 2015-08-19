# nginx-master-playlist-module

this thing only works in special environment, so it's not written to work the way you want


# Example


``bash
 location /master {
                alias /data/stream;
                vod_master_playlist;
                vod_location vod;
                vod_host localhost;
        }
``

then to request master playlist, do this:

``curl "http://cent6/test3.m3u8"``

result:

``
	#EXTM3U
	#EXT-X-STREAM-INF:PROGRAM-ID=1,BANDWIDTH=1560000,RESOLUTION=640x360,CODECS="mp4a.40.2, avc1.4d4015"
	http://localhost/vod/master/test3_360.mp4/index.m3u8
	#EXT-X-STREAM-INF:PROGRAM-ID=1,BANDWIDTH=3120000,RESOLUTION=854x480,CODECS="mp4a.40.2, avc1.4d4015"
	http://localhost/vod/master/test3_480.mp4/index.m3u8
	#EXT-X-STREAM-INF:PROGRAM-ID=1,BANDWIDTH=5120000,RESOLUTION=1280x720,CODECS="mp4a.40.2, avc1.4d4015"
	http://localhost/vod/master/test3_720.mp4/index.m3u3
``


