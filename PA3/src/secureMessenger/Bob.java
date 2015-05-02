//Samuel Davidson, u0835059, 5/1/2015, CS4480.
package secureMessenger;

import java.io.IOException;
import java.net.*;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Bob {
	
	private static boolean DEBUG = true;
	
	//Cryptography
	private static RSAcryptographer rsa;
	private static MessageDigest md;
	private static TripleDEScryptographer TripDes;
	
	//Network
	private static Socket socket;
	private static byte[] buffer = new byte[4096];

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
		
		Log("Building 3DES cipher");
		try {
			TripDes = new TripleDEScryptographer();
		} catch (Exception e) {
			System.out.println("The 3Des cryptographer could not initialize. Exiting...");
			return;
		}
		
		ServerSetup(); //Do all the identity verification.
		
		//The server is set up. Listen for Alice's secret message.
		int read = socket.getInputStream().read(buffer);
		if(read >= buffer.length)
		{
			System.out.println("Message from Alice was too large. Exiting");
			socket.close();
			return;
		}
		if(read < 256)
		{
			System.out.println("Received message was not of an expected size. Exiting.");
			socket.close();
			return;
		}
		Log("Received message from Alice.");
		byte[] encDESkey = new byte[256];
		System.arraycopy(buffer, 0, encDESkey, 0, 256); //The first 256 bytes are the encDESkey
		Log("Encoded 3DES key: " + ToHex(encDESkey));
		byte[] DESkey = rsa.Decrypt(encDESkey, rsa.GetKeys().getPrivate());
		Log("Decoded 3DES key: " + ToHex(DESkey));
		try {
			TripDes.ApplyKey(DESkey);
		} catch (Exception e) {
			System.out.println("The secret key from Alice could not be decoded. Exiting."); // Alice now has Ks!
			socket.close();
			return;
		}
		
		//Time to get message + message digest
		byte[] encMessage = new byte[(read - 256)]; //The remaining after extracting Ks.
		System.arraycopy(buffer, 256, encMessage, 0, (read - 256));
		Log("Encrypted (3DES) message plus encoded Digest: " + ToHex(encMessage));
		byte[] messagePlusDigest = TripDes.Decrypt(encMessage);
		Log("Decrypted (3DES) message plus encoded Digest: " + ToHex(messagePlusDigest));
		byte[] encDigest = new byte[256];
		byte[] messageArray = new byte[messagePlusDigest.length - 256];
		System.arraycopy(messagePlusDigest, 0, encDigest, 0, 256); //Ka-(H(m))
		System.arraycopy(messagePlusDigest, 256, messageArray, 0, messagePlusDigest.length - 256); //m
		byte[] digest = rsa.Decrypt(encDigest, rsa.AliceKey); //H(m)
		Log("Digest of message decrypted with Alice's key: " + ToHex(digest));
		byte[] ourDigest = md.digest(messageArray); // H(m)
		Log("Generated digest of message: " + ToHex(ourDigest));
		
		if(!Arrays.equals(digest, ourDigest))
		{
			System.out.println("Digest from Alice mismatch! Exiting.");
			socket.close();
			return;
		}
		
		String message = new String(messageArray);
		System.out.println("Received secret message from Alice:\n" + message);
		System.out.println("Done.");
		socket.close();
		
		
	}
	
	@SuppressWarnings("resource")
	static void ServerSetup() throws IOException
	{
		System.out.println("You are the server (Bob).\nPort = 2115");
		System.out.println("Awaiting client.");
		
		//Network setup
		socket = new ServerSocket(2115).accept();
		
		//Cryptography setup
		System.out.println("Establishing secure connection.");
		KeyPair myKeys = rsa.GetKeys();
		KeyPair CAkeys = rsa.CAkeys;
		Log("Bob's public key: " + ToHex(myKeys.getPublic().getEncoded()));
		Log("Bob's private key: " + ToHex(myKeys.getPrivate().getEncoded()));
		Log("CA's public key: " + ToHex(CAkeys.getPublic().getEncoded()));
		Log("CA's private key: " + ToHex(CAkeys.getPrivate().getEncoded()));
		Log("Alice's public key: " + ToHex(rsa.AliceKey.getEncoded()));
		
		//Encoding bobs public key
		byte[] encPubKey = rsa.EncodePublicKey(myKeys.getPublic());
		byte[] pubKeyDigest = md.digest(encPubKey);
		Log("Encoded public key: " + ToHex(encPubKey));
		Log("Digest of encoded public key: " + ToHex(pubKeyDigest));
		byte[] secPubKeyDigest = rsa.Encrypt(pubKeyDigest, CAkeys.getPrivate());
		Log("Ecrypted digest using CA K-: " + ToHex(secPubKeyDigest));
		
		//Send it
		socket.getOutputStream().write(encPubKey); //294 bytes long
		socket.getOutputStream().write(secPubKeyDigest); // 256 bytes long
		Log("Sent encoded public and encrypted digest to Alice.");
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
