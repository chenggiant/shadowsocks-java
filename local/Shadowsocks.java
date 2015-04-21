/*

Useful information extracted from Sock5 RFC document: http://tools.ietf.org/html/rfc1928

Version identifier/method selection message:
+----+----------+----------+
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1 to 255 |
+----+----------+----------+
Will be ignored directly.


The SOCKS request is formed as follows:

+----+-----+-------+------+----------+----------+
|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+

Where:

o  VER    protocol version: X'05'
o  CMD
o  CONNECT X'01'
o  BIND X'02'
o  UDP ASSOCIATE X'03'
o  RSV    RESERVED
o  ATYP   address type of following address
o  IP V4 address: X'01'
o  DOMAINNAME: X'03'
o  IP V6 address: X'04'
o  DST.ADDR       desired destination address
o  DST.PORT desired destination port in network octet
order

The server evaluates the request, and
returns a reply formed as follows:

+----+-----+-------+------+----------+----------+
|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+

Where:

o  VER    protocol version: X'05'
o  REP    Reply field:
o  X'00' succeeded
o  X'01' general SOCKS server failure
o  X'02' connection not allowed by ruleset
o  X'03' Network unreachable
o  X'04' Host unreachable
o  X'05' Connection refused
o  X'06' TTL expired
o  X'07' Command not supported
o  X'08' Address type not supported
o  X'09' to X'FF' unassigned
o  RSV    RESERVED
o  ATYP   address type of following address
o  IP V4 address: X'01'
o  DOMAINNAME: X'03'
o  IP V6 address: X'04'
o  BND.ADDR       server bound address
o  BND.PORT       server bound port in network octet order
*/


import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

public class Shadowsocks {
    private SocketAddress serverAddr;
    private Secret secret;
    private Thread serverThread;
    private ServerSocket localSock;
    private boolean running = false;

    Shadowsocks(String remoteServer, int port, String key) {
        serverAddr = new InetSocketAddress(remoteServer, port);
        secret = new Secret(key);
        System.out.println(serverAddr);
    }

    public boolean start(int port) {
        return start("127.0.0.1", port);
    }

    public boolean start(String localServer, int port) {
        if (running) return true;
        ServerSocketChannel channel;
        ListenSocket server;
        try {
            channel = ServerSocketChannel.open();
            localSock = channel.socket();
            localSock.bind(new InetSocketAddress(localServer, port));
            server = new ListenSocket();
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
        serverThread = new Thread(server);
        running = true;
        serverThread.start();
        return true;
    }

    public void join() {
        try {
            serverThread.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    class ListenSocket implements Runnable {

        public void run() {
            try {
                ServerSocketChannel serverChannel = localSock.getChannel();
                while (running) {
                    SocketChannel localChannel = serverChannel.accept();
                    SocketChannel remoteChannel = SetupSocketConnection(localChannel);


//                    ByteBuffer buffer = ByteBuffer.allocate(1024);


                    Router router = new Router(localChannel, remoteChannel);
                    Thread routerThread = new Thread(router);
                    routerThread.start();

                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            running = false;
        }

        private SocketChannel SetupSocketConnection(SocketChannel localChannel) throws IOException {
            SocketChannel remoteChannel = SocketChannel.open(serverAddr);

            Socket remoteSock = remoteChannel.socket();
            Socket localSock = localChannel.socket();

            OutputStream remoteOut;

            InputStream localIn = localSock.getInputStream();
            OutputStream localOut = localSock.getOutputStream();

            int ver = localIn.read();
            if (ver != 5) {
                System.out.println("Unknown protocol version.");
                localSock.close();
            }

            int nMethod = localIn.read();
            localIn.read(new byte[nMethod]); // ignore methods message

            // reply "version(5)/method(0)"
            localOut.write(new byte[]{5, 0});

            byte[] req = new byte[4];
            localIn.read(req); // load VER, CMD, RSV
            if (req[1] != 1) {
                // reply "command not supported"
                byte[] reply = {5, 0, 0, 1, 0, 0, 0, 0, 1, 1};
                localOut.write(reply);
            }

            byte addrType = req[3];
            byte[] addrToSend = new byte[0];
            if (addrType == 1) { // IP address
//                System.out.println("Address is IPv4");
                addrToSend = new byte[5];
            } else if (addrType == 3) { // Domain name
//                System.out.println("Address is a domain name");
                int addrLen = localIn.read();
                addrToSend = new byte[addrLen + 2];
                addrToSend[1] = (byte) addrLen;
                localIn.read(addrToSend, 2, addrLen);
            } else {
                // reply "address type not supported"
                byte[] reply = {5, 8, 0, 1, 0, 0, 0, 0, 1, 1};
                localOut.write(reply);
            }
            addrToSend[0] = addrType;
            byte[] port = new byte[2];
            localIn.read(port);

            // print out the request address and port
            System.out.printf("%s:%d\n", new String(addrToSend), new BigInteger(port).intValue());

            try {
                remoteOut = remoteSock.getOutputStream();
                secret.encrypt(addrToSend);
                secret.encrypt(port);
                remoteOut.write(addrToSend);
                remoteOut.write(port);
            } catch (Exception e) {
                // reply "general SOCKS server failure"
                byte[] reply = {5, 1, 0, 1, 0, 0, 0, 0, 1, 1};
                localOut.write(reply);
            }

            // reply "succeeded"
            byte[] reply = {5, 0, 0, 1, 0, 0, 0, 0, 1, 1};
            localOut.write(reply);

            return remoteChannel;
        }

    }


    class Router implements Runnable {
        public Selector selector;
        SocketChannel localCh;
        SocketChannel remoteCh;

        Router(SocketChannel local, SocketChannel remote) throws IOException {
            selector = Selector.open();
            localCh = local;
            remoteCh = remote;
            localCh.configureBlocking(false);
            remoteCh.configureBlocking(false);
            localCh.register(selector, SelectionKey.OP_READ);
            remoteCh.register(selector, SelectionKey.OP_READ);
        }

        public void run() {
            ByteBuffer buffer = ByteBuffer.allocate(1024);
            try {
                while (running) {
                    int nKey = selector.select();
                    if (nKey <= 0) return;
                    for (SelectionKey key : selector.keys()) {
                        SocketChannel recvCh = (SocketChannel) key.channel();
                        buffer.clear();
                        int read = recvCh.read(buffer);
                        if (read == 0) continue;
                        else if (read == -1) {
                            recvCh.close();
                            if (recvCh == localCh) remoteCh.close();
                            else localCh.close();
                            selector.close();
                            return;
                        }
                        buffer.position(0);
                        byte[] data = new byte[read];
                        buffer.get(data);
                        if (recvCh == localCh) {
                            secret.encrypt(data);
                            buffer.position(0);
                            buffer.put(data);
                            buffer.flip();
                            remoteCh.write(buffer);
//                            System.out.println("I am receiving data to encrypt!!!");
                        } else {
                            secret.decrypt(data);
                            buffer.position(0);
                            buffer.put(data);
                            buffer.flip();
                            localCh.write(buffer);
//                            System.out.println("I am receiving data to decrypt!!!");
                        }
                    }
                    selector.selectedKeys().clear();
                }
            } catch (IOException e) {
                try {
                    selector.close();
                    if (localCh.isConnected()) localCh.close();
                    if (remoteCh.isConnected()) remoteCh.close();
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
        }
    }


    public static void main(String[] args) {
        // default config;
        int localPort = 8388;
        String serverIP = "REMOTE_SERVER_IP";
        int serverPort = 8499;
        String password = "hahaha";

        // if parameters are passed correctly as: <localPort> <serverAddr> <serverPort> <key>
        if (args.length == 4) {
            localPort = Integer.parseInt(args[0]);
            serverIP = args[1];
            serverPort = Integer.parseInt(args[2]);
            password = args[3];
        }

        Shadowsocks s = new Shadowsocks(serverIP, serverPort, password);
        System.out.println("Listening " + localPort + " ...");
        s.start(localPort);
        s.join();
        System.out.println("Stopped.");
    }
}


