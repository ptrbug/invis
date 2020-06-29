简介:
=======
这是一套用来伪装和加密通信的程序, 客户端和服务端同时支持linux, mac os, windows.  
客户在本地同一端口提供socks5和http代理服务  
服务端伪装成第三方https网站  

原理:
=======
根据HelloClient结构体的random值来判断是浏览器请求还是客户端请求.  
如果是浏览器请求: 直接做转发.  
如果是客户端请求: tls握手期间, 明文中的证书会被替换成第三方网的证书，从抓包的角度，这就是和第三方网站的正常通信。但是实际通讯使用的是根据uuid生成的rsa密钥.  

客户端配置:
=======
{  
	"AutoStart" : true, //是否自动重启  
	"ListenAddr" : ":1080", //socks5和http的监听地址  
	"ServerAddr": "127.0.0.1:443", //服务端地址  
	"Channel" : "cc7aff1d-ef9c-4cf1-b2d8-c0dd83f0ff16", //通信uuid,和服务端保持一致  
	"Client" : "a5f8f489-de00-4865-8263-9b7e04e0f252",  //用户uuid, 服务端也需要配置  
	"FakeWebDomain" : "break.com"   //伪造网站的域名, 和服务端保持一致  
}

服务端配置:
=======
{
	"FakeWebURL" : "https://break.com/",    //这是填你要伪造网站的域名  
	"FrontedListenAddr" : ":443",           //对外监听端口  
	"Channel" : "cc7aff1d-ef9c-4cf1-b2d8-c0dd83f0ff16", //通信uuid  
	"Clients" : [
        //用户uuid和对应的内部监听地址, 根据不同用户uuid, 将端口443的数据转发到相应的端口。  
         {"ID": "a5f8f489-de00-4865-8263-9b7e04e0f252", "ListenAddr":"127.0.0.1:7001"},   
         {"ID": "a7ea4655-1dd1-2964-1444-341067dfd885", "ListenAddr":"127.0.0.1:7002"}  
        ]
}