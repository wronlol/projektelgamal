package com.za.crypto.elgamal.server;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import javax.json.Json;
import javax.json.JsonObject;
public class ServerThread extends Thread {
	private Server server;
	private BufferedReader bufferedReader;
	private PrintWriter printWriter; 
	public ServerThread(Socket socket, Server server) throws IOException {
		this.server = server;
		this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		this.printWriter = new PrintWriter(socket.getOutputStream(), true);
	}
	public void run() {
		JsonObject jsonObject = null;
		try { 
			while(true) {
				jsonObject = Json.createReader(bufferedReader).readObject();  
				System.out.println("\n[system]: "+jsonObject.toString());
				server.forwardMessage(jsonObject.toString(), this);
				if (jsonObject.containsKey("alpha")) 
					System.out.println("[Passive Eve]: have p, alpha, & beta for "+jsonObject.getString("name"));
				else if (jsonObject.containsKey("ephermalKey")) {
					System.out.println("[Passive Eve]: in order to obtain d or i, need to solve one of 2 DLP problems:");
					System.out.println("[Passive Eve]: (1) to obtain d solve following DLP ==> d = logBaseAlpha(beta) mod p");
					System.out.println("[Passive Eve]:     & calculate masking key ==> maskingKey <congruent> ephermalKey^d mod p");
					System.out.println("[Passive Eve]: (2) to obtain i solve following DLP ==> i = logBaseAlpha(ephermalKey) mod p");
					System.out.println("[Passive Eve]:     & calculate masking key ==> maskingKey <congruent> beta^i mod p");
					System.out.println("[Passive Eve]: finally decrypt message ==> x <congruent> y*maskingKey^(-1) mod p");
				}
			} 
		} catch (Exception e) { server.getServerThreads().remove(this);}
	}
	void forwardMessage(String message) { printWriter.println(message); }
}
