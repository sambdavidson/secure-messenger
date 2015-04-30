package secureMessenger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;

public class Alice {

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
		
		System.out.println("Secure Messenger - Alice");
		System.out.println("Samuel Davidson - u0835059");
		
		Log("Building RSA cipher");
		try {
			rsa = new RSAcryptographer("Alice");
		} catch (Exception e) {
			System.out.println("The RSA Cryptographer could not initialize. Exiting...");
			return;
		}
		
		sysReader = new BufferedReader(new InputStreamReader(System.in)); //Prepare for reading
		ClientSetup();

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
			
			socketIn = new InputStreamReader(socket.getInputStream());
			socketOut = new PrintWriter(socket.getOutputStream());
		}
		System.out.println("Connected.");
		
		//Cryptography setup
		System.out.println("Establishing secure connection.");
		KeyPair myKeys = rsa.GetKeys();
		KeyPair CAkeys = rsa.CAkeys;
		//Receive bob's public key
		int read = socket.getInputStream().read(buffer);
		byte[] secPubKey = new byte[read];
		System.arraycopy(buffer, 0, secPubKey, 0, read);
		byte[] bobPubKeyEnc = rsa.Decrypt(secPubKey, CAkeys.getPublic());
		bobPublicKey = rsa.DecodePublicKey(bobPubKeyEnc);
		if(bobPublicKey == null)
		{
			System.err.println("Could not receive Bob's public key!");
			socket.close();
			return;
		}
		System.out.println("BobsKeyReceivedCorrectly");
		//Bobs key received correctly
		
	}
	
	static void Log(String str)
	{
		if(DEBUG)
		{
			System.err.println("Debug:\t" + str);
		}
	}

}
