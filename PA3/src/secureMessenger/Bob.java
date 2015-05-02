package secureMessenger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.*;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class Bob {
	
	private static boolean DEBUG = true;
	private static BufferedReader sysReader;
	
	//Cryptography
	private static RSAcryptographer rsa;
	private static MessageDigest md;
	private static PublicKey bobPublicKey;
	
	//Network
	private static Socket socket;
	private static byte[] buffer = new byte[2048];
	private static InputStreamReader socketIn;
	private static PrintWriter socketOut;

	public static void main(String[] args) throws IOException {
		
		if(args.length > 0 && args[0] == "-v") //Debugging
		{
			DEBUG = true;
		}
		
		System.out.println("Secure Messenger - Bob");
		System.out.println("Samuel Davidson - u0835059");
		
		Log("Building RSA cipher");
		try {
			rsa = new RSAcryptographer("Bob");
		} catch (Exception e) {
			System.out.println("The RSA Cryptographer could not initialize. Exiting...");
			return;
		}
		
		Log("Building SHA1 digester");
		try {
			md = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("The SHA-1 message digest could not initialize. Exiting...");
			return;
		}
		
		sysReader = new BufferedReader(new InputStreamReader(System.in)); //Prepare for reading
		ServerSetup();
	}
	
	static void ServerSetup() throws IOException
	{
		System.out.println("You are the server (Bob).\nPort = 2115");
		System.out.println("Awaiting client.");
		
		//Network setup
		ServerSocket server = new ServerSocket(2115);
		
		socket = server.accept();
		socketIn = new InputStreamReader(socket.getInputStream());
		socketOut = new PrintWriter(socket.getOutputStream());
		
		//Cryptography setup
		System.out.println("Establishing secure connection.");
		KeyPair myKeys = rsa.GetKeys();
		KeyPair CAkeys = rsa.CAkeys;
		byte[] encPubKey = rsa.EncodePublicKey(myKeys.getPublic());
		byte[] pubKeyDigest = md.digest(encPubKey);
		Log("Encoded public key: " + ToHex(encPubKey));
		Log("Digest of encoded public key: " + ToHex(pubKeyDigest));
		byte[] secPubKeyDigest = rsa.Encrypt(pubKeyDigest, CAkeys.getPrivate());
		System.out.println(secPubKeyDigest.length);
		Log("Ecrypted digest using CA K-: " + ToHex(secPubKeyDigest));
		socket.getOutputStream().write(encPubKey); //X bytes long
	}
	/***
	 * Debug text that prints when the command line argument "-v" is used.
	 * @param str
	 */
	static void Log(String str)
	{
		if(DEBUG)
		{
			System.err.println("\nDebug:\t" + str);
		}
	}
	
	static String ToHex(byte[] input)
	{
		StringBuilder sb = new StringBuilder();
		for(byte b: input)
		{
			sb.append(String.format("%02X ", b));
		}
		return sb.toString();
	}

}
