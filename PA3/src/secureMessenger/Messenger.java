package secureMessenger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.*;
import java.security.KeyPair;
import java.security.PublicKey;

public class Messenger {
	
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
		
		System.out.println("Secure Messenger");
		System.out.println("Samuel Davidson - u0835059");
		
		Log("Building RSA cipher");
		try {
			rsa = new RSAcryptographer();
		} catch (Exception e) {
			System.out.println("The RSA Cryptographer could not initialize. Exiting...");
			return;
		}
		
		sysReader = new BufferedReader(new InputStreamReader(System.in)); //Prepare for reading
		int choice = 0;
		while(choice != 1 || choice != 2) //Decision making
		{
			System.out.println("\n1 - Server (Bob) \t2 - Client (Alice)");
			System.out.println("Are you 1 or 2?");
			try{
	            choice = Integer.parseInt(sysReader.readLine());
	        }catch(NumberFormatException nfe){
	            System.out.println("Invalid Format!");
	        }
		}
		if(choice == 1) //SERVER
		{
			ServerSetup();
		}
		else if (choice == 2) //Client
		{
			ClientSetup();
		}

	}
	
	static void ServerSetup() throws IOException
	{
		System.out.println("You are the server (Bob).\nPort = 2115");
		System.out.println("Awaiting client.");
		
		//Network setup
		ServerSocket server = new ServerSocket(2121); 
		socket = server.accept();
		socketIn = new InputStreamReader(socket.getInputStream());
		socketOut = new PrintWriter(socket.getOutputStream());
		
		//Cryptography setup
		System.out.println("Establishing secure connection.");
		KeyPair myKeys = rsa.GetKeys();
		KeyPair CAkeys = rsa.CAkeys;
		byte[] encPubKey = rsa.EncodePublicKey(myKeys.getPublic());
		byte[] secPubKey = rsa.Encrypt(encPubKey, CAkeys.getPrivate());
		socket.getOutputStream().write(secPubKey);
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
				System.out.println("Error connecting to host.");
				e.printStackTrace();
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
