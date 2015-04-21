# shadowsocks-java


shadowsocks-java is a lightweight tunnel proxy which can help you get through firewalls. It is a java port of [shadowsocks](https://github.com/shadowsocks/shadowsocks).

In this version, only TABLE encryption is supported.

For daily usage, please use the [stable version](https://github.com/shadowsocks/shadowsocks)


## Description

### Server
- Configure the settings in `config.json` in server folder, then copy `config.json` and `server.py` to remote server

````json
{
    "server":"REMOTE_SERVER_IP",
    "server_port":8499,
    "local_port":8388,
    "password":"hahaha",
    "timeout":600
}
````

- Run `python server.py`


### Client

- Configure the settings in `main()` of `Shadowsocks.java` in local folder, then compile the program using `javac Shadowsocks.java`

````java
// default config;
int localPort = 8388;
String serverIP = "REMOTE_SERVER_IP";
int serverPort = 8499;
String password = "hahaha";

````

- Run `java Shadowsocks`

- Or run with your server parameters `java Shadowsocks <localPort> <serverAddr> <serverPort> <key>`
