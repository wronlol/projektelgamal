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
					System.out.println("[SERWER]: Otrzymano p, alpha, & beta dla "+jsonObject.getString("name"));
				else if (jsonObject.containsKey("ephermalKey")) {
					System.out.println("[SERWER]: Aby otrzymac d lub i, jedno z dwoch rownan:");
					System.out.println("[SERWER]: (1) aby otrzymac d rozwiaz to rownanie ==> d = logBaseAlpha(beta) mod p");
					System.out.println("[SERWER]:     & i obliczyc klucz maskujacy ==> klucz maskujacy <kongruentna> kluczEfemeryczny^d mod p");
					System.out.println("[SERWER]: (2) aby otrzymac i rozwiaz to rownanie ==> i = logBaseAlpha(kluczEfemeryczny) mod p");
					System.out.println("[SERWER]:     i oblicz klucz maskujacy ==> klucz maskujacy <kongruentna> beta^i mod p");
					System.out.println("[SERWER]: i w koncu odszyfruj wiadomosc ==> x <kongruentna> y*kluczMaskujacy^(-1) mod p");
				}
			} 
		} catch (Exception e) { server.getServerThreads().remove(this);}
	}
	void forwardMessage(String message) { printWriter.println(message); }
}
