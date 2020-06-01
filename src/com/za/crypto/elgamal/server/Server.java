package com.za.crypto.elgamal.server;
import java.io.IOException;
import java.net.ServerSocket;
import java.util.HashSet;
import java.util.Set;
public class Server {
	static final int PORT = 4444; 
	private ServerSocket serverSocket;
	private Set<ServerThread> serverThreads = new HashSet<ServerThread>();
	public Set<ServerThread> getServerThreads() { return serverThreads; }
	public static void main(String[] args) throws IOException {
		Server server = new Server();
		server.serverSocket = new ServerSocket(PORT);
		System.out.println("Pasywne sluchanie calej komunikacji");
		while (true) {
			ServerThread serverThread = new ServerThread(server.serverSocket.accept(), server);
			server.serverThreads.add(serverThread);
			serverThread.start();
		}
	}
	void forwardMessage(String message, ServerThread originatingT) {
		serverThreads.stream().filter(t -> t != originatingT).forEach(t -> t.forwardMessage(message)); 
	}
}
