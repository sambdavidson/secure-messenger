package secureMessenger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.*;
import java.security.KeyPair;
import java.security.PublicKey;

public class Bob {
	
	private static boolean DEBUG = true;
	private static BufferedReader sysReader;
	
	//Cryptography
	private static RSAcryptographer rsa;
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
		byte[] plnPubKey = myKeys.getPublic().getEncoded();
		byte[] CAK = CAkeys.getPrivate().getEncoded();
		System.out.println(encPubKey.length + " | " + CAK.length);
		byte[] secPubKey = rsa.Encrypt(plnPubKey, myKeys.getPublic());
		socket.getOutputStream().write(secPubKey);
	}
	
	static void Log(String str)
	{
		if(DEBUG)
		{
			System.err.println("\nDebug:\t" + str);
		}
	}

}
