package com.za.crypto.elgamal.serverconsole;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.stream.IntStream;
import javax.json.Json;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Client {
	public static boolean ASCII_FLAG = false;
	private String name = null;
	private PrintWriter printWriter;
	private String otherPartyName = null;
	private BigInteger p = null;
	private BigInteger alpha = null;
	private BigInteger d = null;
	private BigInteger beta = null;
	private BigInteger otherPartyP = null;
	private BigInteger otherPartyAlpha = null;
	private BigInteger otherPartyBeta = null;
	private boolean readyFlag = false;
	public static void main(String[] args) throws UnknownHostException, IOException {
		if (ASCII_FLAG) System.out.println("[system]: running in ascii mode...");
		BufferedReader bR = new BufferedReader(new InputStreamReader(System.in));
		Client client = new Client();
		ElgamalHelper elgamalHelper = new ElgamalHelper(client);
		Socket socket = new Socket("localhost", 4444);
		client.printWriter = new PrintWriter(socket.getOutputStream(), true);
		new ClientThread(socket, client).start();
		client.communicate(elgamalHelper.handleSetupPhase(), bR);
	}
	private void communicate(ElgamalHelper elgamalHelper, BufferedReader bR) throws IOException {
		while (true) {
			if (getOtherPartyAlpha() != null && !readyFlag) {
				System.out.println("[system]: ready to send & receive messages, or e:xit");
				readyFlag = true;
			}
			
			//String content = new String(Files.readAllBytes(Paths.get("/home/kali/Desktop/tbk/projekt/abc.txt")));
			String content = bR.readLine();
			String xString = content;
			
			if (xString.equals("e")) System.exit(0);
			BigInteger i = null;
			while (true){
				try {
					System.out.println("[system]: enter one time private key i from set {2,...,"+otherPartyName+"P-2}");
					i = new BigInteger(bR.readLine()); 
					break;
				} catch (Exception e) {System.out.println("invalid entry.");};
			}
			BigInteger ephermalKey = otherPartyAlpha.modPow(i, otherPartyP);
			System.out.println("["+name+"]: calculate one time public key ==> ephermalKey <congruent> "
														+otherPartyName+"Alpha^i mod "+otherPartyName+"P = "+ephermalKey);
			BigInteger maskingKey = otherPartyBeta.modPow(i, otherPartyP);
			System.out.println("[" + name + "]: calculate one time masking key ==> maskingKey <congruent> "+otherPartyName
														+"Beta^i mod "+otherPartyName+"P = "+maskingKey);
			StringBuffer xStringBuffer = new StringBuffer();
			if (!ASCII_FLAG) {
				IntStream.range(0, xString.length()).forEach( index -> 
					xStringBuffer.append(characterToAscii(xString.charAt(index)) + " "));
				System.out.println("[" + name + "]: map char to ascii ==> " + xStringBuffer.toString());
			} else {
				String[] xStringTokens = xString.split(" ");
				IntStream.range(0, xStringTokens.length).forEach(index -> xStringBuffer.append(xStringTokens[index] + " "));
			}	
			String yString = ElgamalHelper.encryptMessage(xStringBuffer.toString(), maskingKey, otherPartyP);
			System.out.println("[" + name + "]: encrypt ascii message ==> y <congruent> x*maskingKey mod "+otherPartyName+"P = " + yString);
			StringWriter sW = new StringWriter();
			Json.createWriter(sW).writeObject(
					         Json.createObjectBuilder()
					             .add("name", name)
					             .add("ephermalKey", ephermalKey.toString())
					             .add("y", yString).build());
			System.out.println("[" + name + "]: send "+sW.toString()+"\n");
			printWriter.println(sW);
		}
	}
	public String getName() { return name; }
	public PrintWriter getPrintWriter() { return printWriter; }
	public BigInteger getP() { return p; }
	public BigInteger getAlpha() { return alpha; }
	public BigInteger getD() { return d; }
	public BigInteger getBeta() { return beta; }
	public BigInteger getOtherPartyP() { return otherPartyP; }
	public BigInteger getOtherPartyAlpha() { return otherPartyAlpha; }
	public BigInteger getOtherPartyBeta() { return otherPartyBeta; }
	public String getOtherPartyName() { return otherPartyName; }
	public void setName(String name) { this.name = name; }
	public void setP(BigInteger p) { this.p = p; }
	public void setAlpha(BigInteger alpha) { this.alpha = alpha; }	
	public void setD(BigInteger d) { this.d = d; }
	public void setBeta(BigInteger beta) { this.beta = beta; }
	public void setOtherPartyP(BigInteger otherPartyP) { this.otherPartyP = otherPartyP; }
	public void setOtherPartyAlpha(BigInteger otherPartyAlpha) { this.otherPartyAlpha = otherPartyAlpha; }
	public void setOtherPartyBeta(BigInteger otherPartyBeta) { this.otherPartyBeta = otherPartyBeta; }
	public void setOtherPartyName(String otherPartyName) { this.otherPartyName = otherPartyName; }
	public void setReadyFlag(boolean readyFlag) { this.readyFlag = readyFlag; }
	static int characterToAscii(char character) { return (int) character; }
	static char asciiToCharacter(int ascii) { return (char) ascii; }
}
