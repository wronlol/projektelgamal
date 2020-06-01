package com.za.crypto.elgamal.client;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.Socket;
import java.util.Arrays;
import java.util.stream.IntStream;
import javax.json.Json;
import javax.json.JsonObject;
public class ClientThread extends Thread {
	private BufferedReader reader;
	private Client client;
	public ClientThread(Socket socket, Client client) throws IOException {
		this.reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));	
		this.client = client;
	}
	public void run() {
		boolean flag = true;
		while (true) {
			JsonObject jsonObject = Json.createReader(reader).readObject();
			if (jsonObject.containsKey("p") && client.getOtherPartyP() == null) {
				client.setOtherPartyP(new BigInteger(jsonObject.getString(("p"))));
				client.setOtherPartyAlpha(new BigInteger(jsonObject.getString(("alpha"))));
				client.setOtherPartyName(jsonObject.getString(("name")));
				client.setOtherPartyBeta(new BigInteger(jsonObject.getString(("beta"))));
				System.out.println("[system]: receive "+jsonObject.toString());
				if (client.getAlpha() == null) 
					System.out.println("[system]: enter name, (prime #) p, (primitive element) alpha, & (private key) d from set {2,...,p-2}");
				if (client.getAlpha() != null && flag) {
					System.out.println("[system]: Podaj nazwe  pliku do wyslania lub wpisz e:xit aby wyjsc");
					flag = false;
					client.setReadyFlag(true);
				}
			} else if (jsonObject.containsKey("y")) handleIncomingMessage(jsonObject);
		}
	}
	private void handleIncomingMessage(JsonObject jsonObject) {
		System.out.println("["+client.getName()+"]: receive "+jsonObject.toString());
		String yString = jsonObject.getString("y");
		String ephermalKey = jsonObject.getString("ephermalKey");
		BigInteger maskingKey = new BigInteger(ephermalKey).modPow(client.getD(), client.getP());
		String name = "["+client.getName()+"]:";
		System.out.println(name+" calculate one time masking key ==> maskingKey <congruent> ephermalKey^d mod p = "+maskingKey);
		BigInteger[] x = ElgamalHelper.decryptMessage(yString, maskingKey, client.getP());
		System.out.println(name+" decrypt ciphertext ==> x <congruent> y*maskingKey^(-1) mod p = "+ Arrays.toString(x));
		StringBuffer xStringBuffer = new StringBuffer(); 
		if (!Client.ASCII_FLAG) {
			IntStream.range(0, x.length).forEach(index -> xStringBuffer.append(
								Client.asciiToCharacter(x[index].intValue())));
			System.out.println(name+" map asii to char  & obtain original message ==> " + xStringBuffer.toString());
		} else {
			IntStream.range(0, x.length).forEach(
								index -> xStringBuffer.append(x[index].intValue() + " "));
		}
		System.out.println("["+client.getOtherPartyName() +"]: "+ xStringBuffer.toString());
	}
}
