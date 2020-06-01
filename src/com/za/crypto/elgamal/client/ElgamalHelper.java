package com.za.crypto.elgamal.client;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.util.stream.IntStream;
import javax.json.Json;
public class ElgamalHelper {
	private Client client = null;
	public ElgamalHelper(Client client) { this.client = client; }
	ElgamalHelper handleSetupPhase() throws IOException {
		while (true) {
			if (client.getName() == null) {
				BufferedReader bR = new BufferedReader(new InputStreamReader(System.in));
				StringWriter sW = new StringWriter();
				while (true) {
					try {
						System.out.println("[system]: enter name, (prime #) p, (primitive element) alpha, & (private key) d from set {2,...,p-2}");
						String[] params = bR.readLine().split(" ");
						client.setName(params[0]);
						client.setP(new BigInteger(params[1]));
						client.setAlpha(new BigInteger(params[2]));
						client.setD(new BigInteger(params[3]));
					    break;
					} catch (Exception e) {System.out.println("invalid entry.");}
				}
				client.setBeta(client.getAlpha().modPow(client.getD(), client.getP()));
				System.out.println("["+client.getName()+"]: calculate public key ==> beta = alpha^d mod p = "+client.getBeta());
				Json.createWriter(sW).writeObject(
							     Json.createObjectBuilder()
									 .add("name", client.getName())
									 .add("p", client.getP().toString())
									 .add("alpha", client.getAlpha().toString())
									 .add("beta", client.getBeta().toString()).build());
				System.out.println("["+client.getName()+"]: send "+sW.toString());
				client.getPrintWriter().println(sW);
				break;
			}
		}
		return this;
	}
	static String encryptMessage(String xString, BigInteger maskingKey, BigInteger p) {
		String[] xStringTokens = xString.split(" ");
		BigInteger[] y = new BigInteger[xStringTokens.length];
		IntStream.range(0, xStringTokens.length).forEach(i -> 
				y[i] = (new BigInteger(xStringTokens[i]).multiply(maskingKey)).mod(p));
		StringBuffer yStringBuffer = new StringBuffer();
		for (int i = 0; i < y.length; i++) { yStringBuffer.append(y[i] + " "); }
		return yStringBuffer.toString();
	}
	static BigInteger[] decryptMessage(String yString, BigInteger maskingKey, BigInteger p) {
		String[] yStringTokens = yString.trim().split(" ");
		BigInteger[] x = new BigInteger[yStringTokens.length];
		for (int i = 0; i < yStringTokens.length; i++)
			x[i] = (new BigInteger(yStringTokens[i])).multiply(maskingKey.modInverse(p)).mod(p);
		return x;
	}
}
