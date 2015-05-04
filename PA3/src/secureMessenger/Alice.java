//Samuel Davidson, u0835059, 5/1/2015, CS4480.
package secureMessenger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;

public class Alice {

	private static boolean DEBUG = true;
	private static BufferedReader sysReader;
	
	//Cryptography
	private static RSAcryptographer rsa;
	private static MessageDigest md;
	private static TripleDEScryptographer TripDes;
	private static PublicKey bobPublicKey;
	
	//Network
	private static Socket socket;

	public static void main(String[] args) throws IOException {
		
		if(args.length > 0) //Debugging
		{
			DEBUG = true;
		}
		
		System.out.println("Secure Messenger - Alice");
		System.out.println("Samuel Davidson - u0835059");
		Log("Building RSA cipher");
		try {
			rsa = new RSAcryptographer("Alice");
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
		
		sysReader = new BufferedReader(new InputStreamReader(System.in)); //Prepare for reading
		
		ClientSetup(); //Sets everything up and verifies Bob's identity.
		
		if(bobPublicKey == null) //Check if we returned before the end.
		{
			return;
		}
		String secretMessage = "Bob, I love CS4480. Sincerely, Alice."; // m
		System.out.println("Sending secret message: " + secretMessage);
		byte[] digestSM = md.digest(secretMessage.getBytes()); // H(m)
		Log("Digest of secret message: " + ToHex(digestSM));
		byte[] encDigestSM = rsa.Encrypt(digestSM, rsa.GetKeys().getPrivate()); // Ka-(H(m))
		Log("Encrypted digest of secret message: " +  ToHex(encDigestSM)); 
		byte[] arraySM = secretMessage.getBytes();
		byte[] digestPlusSM = new byte[arraySM.length + encDigestSM.length];
		
		//Create the array [EncDigest + SecretMessage]
		System.arraycopy(encDigestSM, 0, digestPlusSM, 0, 128);
		System.arraycopy(arraySM, 0, digestPlusSM, encDigestSM.length, arraySM.length);// [Ka-(H(m)),SM]
		byte[] encMessage = TripDes.Encrypt(digestPlusSM); // Ks(.)
		Log("Entire ecrypted message plus digest: " + ToHex(encMessage));
		
		//Encrypt Ks with Bob's public key.
		byte[] encKey = rsa.Encrypt(TripDes.GetKey().getEncoded(), bobPublicKey); //128 bytes in length
		Log("3DES key encrypted with Bob's public: " + ToHex(encKey));
		
		//Create the final message
		byte[] messageFinal = new byte[encKey.length + encMessage.length];
		System.arraycopy(encKey, 0, messageFinal, 0, 128);
		System.arraycopy(encMessage, 0, messageFinal, 128, encMessage.length);
		socket.getOutputStream().write(messageFinal);
		Log("Final message sent to Bob: " + ToHex(messageFinal));
		//WE DID IT! Hopefully Bob gets our secret message!
		
	}
	
	
	static void ClientSetup() throws IOException
	{
		System.out.println("You are a client (Alice).");
		
		while(socket == null) //Connection Setup
		{
			System.out.println("Input the Host(IP):");
			String host = sysReader.readLine();
			int port = 0;
			while(port < 1023 || port > 65535)
			{
				System.out.println("Input the port:");
				try{
					port = Integer.parseInt(sysReader.readLine());
		        }catch(NumberFormatException nfe){
		            System.out.println("Invalid Format!");
		        }
			}
			try
			{
			socket = new Socket(host, port);	
			}
			catch (Exception e)
			{
				System.out.println("Error connecting to host: " + e.getMessage());
				continue;
			}
			
		}
		System.out.println("Connected.");
		
		//Cryptography setup
		System.out.println("Establishing secure connection.");
		KeyPair CAkeys = rsa.CAkeys;
		KeyPair myKeys = rsa.GetKeys();
		Log("Alice's public key: " + ToHex(myKeys.getPublic().getEncoded()));
		Log("Alice's private key: " + ToHex(myKeys.getPrivate().getEncoded()));
		Log("CA's public key: " + ToHex(CAkeys.getPublic().getEncoded()));
		
		//Receive bob's public key
		int encKeySize = 162;
		byte[] encPubKey = new byte[encKeySize];
		int received = socket.getInputStream().read(encPubKey);
		Log("Received Bob's encoded public key: " + ToHex(encPubKey));
		if(received != encKeySize)
		{
			System.out.println("ERROR Receiving! Expected " + encKeySize + " Actual " + received);
		}
		
		//Receive the digest of the key.
		int digestKeySize = 256;
		byte[] secPubKeyDigest = new byte[256];
		received = socket.getInputStream().read(secPubKeyDigest);
		Log("Received the encrypted digest of Bob's public key: " + ToHex(secPubKeyDigest));
		if(received != digestKeySize)
		{
			System.out.println("ERROR Receiving! Expected " + digestKeySize + " Actual " + received);
		}
		
		//Generate our own digest and compare
		byte[] BobPubKeyDigest = rsa.Decrypt(secPubKeyDigest, CAkeys.getPublic());
		Log("Decripted digest: " + ToHex(BobPubKeyDigest));
		byte[] expectedDigest = md.digest(encPubKey);
		Log("Generated digest of encoded Bob's public key: " + ToHex(BobPubKeyDigest));
		if(!Arrays.equals(BobPubKeyDigest, expectedDigest))
		{
			System.out.println("The authenticity of Bob could not be verified. Exiting.");
			socket.close();
			return;
		}
		
		//Bob has been verified!!
		bobPublicKey = rsa.DecodePublicKey(encPubKey);
		if(bobPublicKey == null)
		{
			System.err.println("Could not decode Bob's public key. Exiting.");
			socket.close();
			return;
		}
		
		//I would say we are done with the setup.
		
		
	}
	
	static void Log(String str)
	{
		if(DEBUG)
		{
			System.err.println("Debug:\t" + str);
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
