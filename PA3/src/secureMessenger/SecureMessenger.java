// Samuel Davidson
// https://github.com/samdamana

package secureMessenger;

import java.io.IOException;
import java.net.*;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.swing.SwingUtilities;

public class SecureMessenger implements Runnable {

	private MessengerFrame GUI;
	public boolean isHost = false;
	
	//Cryptography
	private RSAcryptographer rsa;
	private MessageDigest md;
	private TripleDEScryptographer TripDes;
	private Key otherPublicKey;
	private int encodedKeySize;
	
	//Network
	private Socket socket;
	public int port;
	public String host;
	private byte[] buffer = new byte[4096];

	public SecureMessenger(MessengerFrame frame)
	{
		GUI = frame;
		Log("Building RSA cipher");
		try {
			rsa = new RSAcryptographer("User");
		} catch (Exception e) {
			Log("The RSA Cryptographer could not initialize.");
			return;
		}
		encodedKeySize = rsa.EncodedKeySize;
		
		Log("Building SHA1 digester");
		try {
			md = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			Log("The SHA-1 message digest could not initialize.");
			return;
		}
		
		Log("Building 3DES cipher");
		try {
			TripDes = new TripleDEScryptographer();
		} catch (Exception e) {
			Log("The 3Des cryptographer could not initialize.");
			return;
		}
	}
	
	private void listenLoop() throws IOException
	{
		String name = "Client";
		if(isHost)
			name = "Host";
		while(true)
		{
			int read = socket.getInputStream().read(buffer);
			if(read == -1)
			{
				Log("Connection lost.");
				GUI.isSending(false);
				socket.close();
				return;
			}
			byte[] message = new byte[read];
			System.arraycopy(buffer, 0, message, 0, read);
			message = TripDes.Decrypt(message);
			Log(name + ":\n" + new String(message));
		}
	}
	public void Send(String message)
	{
		byte[] toSend = TripDes.Encrypt(message.getBytes());
		try {
			socket.getOutputStream().write(toSend);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	@SuppressWarnings("resource")
	public void ServerSetup(int port) throws IOException
	{
		Log("You are hosting at port " + port + ".");
		Log("Awaiting client...");
		
		//Network setup
		socket = new ServerSocket(port).accept();
		
		//Cryptography setup
		Log("Establishing secure connection.");
		KeyPair myKeys = rsa.GetKeys();
		KeyPair CAkeys = rsa.CAkeys;
		byte[] pubKeyPlusEncHash = encryptDigestPlusMessage(rsa.EncodePublicKey(myKeys.getPublic()), CAkeys.getPrivate());
		socket.getOutputStream().write(pubKeyPlusEncHash);
		
		//Receive from client their pub and a hash.
		pubKeyPlusEncHash = new byte[128 + rsa.EncodedKeySize]; // enc(SHA1) + 162 key size
		socket.getInputStream().read(pubKeyPlusEncHash);
		byte[] encHash = new byte[128];
		System.arraycopy(pubKeyPlusEncHash, 0, encHash, 0, encHash.length);
		byte[] encClientPubKey = new byte[rsa.EncodedKeySize];
		System.arraycopy(pubKeyPlusEncHash, 128, encClientPubKey, 0, rsa.EncodedKeySize);
		byte[] recHash = rsa.Decrypt(encHash, rsa.GetKeys().getPrivate());
		byte[] myHash = md.digest(encClientPubKey);
		if(!Arrays.equals(recHash, myHash))
		{
			Log("Could not verify client's hash.");
			return;
		}
		otherPublicKey = rsa.DecodePublicKey(encClientPubKey);
		
		//Send the client the 3DES key.
		byte[] enc3DES = rsa.Encrypt(TripDes.GetKey().getEncoded(), otherPublicKey);
		byte[] desedeMessage = encryptDigestPlusMessage(enc3DES, otherPublicKey);
		socket.getOutputStream().write(desedeMessage);
		
		//Read welcome message.
		int read = socket.getInputStream().read(buffer);
		if(read == -1)
		{
			Log("Connection closed.");
			socket.close();
			return;
		}
		byte[] welcomeMessage = new byte[read];
		System.arraycopy(buffer, 0, welcomeMessage, 0, read);
		Log("Host Says:\n" + new String(TripDes.Decrypt(welcomeMessage)));
	}
	
	public void ClientSetup(String host, int port) throws IOException
	{
		Log("Connecting to host...");
		
		socket = new Socket(host,port);
		
		Log("Connected.");
		
		//Cryptography setup
		Log("Establishing secure connection.");
		KeyPair myKeys = rsa.GetKeys();
		KeyPair CAkeys = rsa.CAkeys;
		
		//Receive the digest of the key.
		int digestKeySize = 256;
		byte[] secPubKeyDigest = new byte[digestKeySize];
		int received = socket.getInputStream().read(secPubKeyDigest);
		if(received != digestKeySize)
		{
			Log("ERROR Receiving! Expected " + digestKeySize + " Actual " + received);
		}
		
		//Receive other's public key
		byte[] encPubKey = new byte[encodedKeySize];
		received = socket.getInputStream().read(encPubKey);
		if(received != encodedKeySize)
		{
			Log("ERROR Receiving! Expected " + encodedKeySize + " Actual " + received);
		}
		
		//Generate our own digest and compare
		byte[] otherDigest = rsa.Decrypt(secPubKeyDigest, CAkeys.getPublic());
		byte[] expectedDigest = md.digest(encPubKey);
		if(!Arrays.equals(otherDigest, expectedDigest))
		{
			Log("The authenticity of the host could not be verified. Exiting.");
			socket.close();
			return;
		}		
		//Other has been verified!!
		otherPublicKey = rsa.DecodePublicKey(encPubKey);
		if(otherPublicKey == null)
		{
			Log("Could not decode the host's public key.");
			socket.close();
			return;
		}
		
		//Send our own public key.
		byte[] encDigPlMess = encryptDigestPlusMessage(rsa.EncodePublicKey(myKeys.getPublic()), otherPublicKey);
		
		socket.getOutputStream().write(encDigPlMess);
		
		//Receive the 3DES key.
		
		byte[] encDigest = new byte[128];
		socket.getInputStream().read(encDigest);

		byte[] encryptedDesedeKey = new byte[128];
		socket.getInputStream().read(encryptedDesedeKey);
		otherDigest = rsa.Decrypt(encDigest, rsa.GetKeys().getPrivate());
		expectedDigest = md.digest(encryptedDesedeKey);

		
		if(!Arrays.equals(otherDigest, expectedDigest))
		{
			Log("Error receiving the host's 3DES key.");
			socket.close();
			return;
		}
		byte[] desedeKey = rsa.Decrypt(encryptedDesedeKey, rsa.GetKeys().getPrivate());
		try 
		{
			TripDes.ApplyKey(desedeKey);
		} 
		catch (Exception e) 
		{
			Log("Error decoding the host's 3DES key.");
			socket.close();
			return;
		}
		//SECURE CONNECTION HAS BEEN ESTABLISHED!
		
		byte[] welcomeMessage = TripDes.Encrypt("You may now send me secure messages!".getBytes());
		socket.getOutputStream().write(welcomeMessage);
		
	}
	/**
	 * Outputs the message in the form [(encrypted digest) + message]
	 * The encrypted digest is the first 256 bytes
	 * @param message
	 * @param key
	 * @return output array
	 */
	private byte[] encryptDigestPlusMessage(byte[] message, Key key)
	{
		byte[] digest = md.digest(message);
		byte[] encDigest = rsa.Encrypt(digest, key);
		byte[] output = new byte[encDigest.length + message.length];
		System.arraycopy(encDigest, 0, output, 0, encDigest.length);
		System.arraycopy(message, 0, output, encDigest.length, message.length);
		return output;
	}
	/**
	 * Prints to the output box on the frame.
	 * @param str
	 */
	private void Log(String str)
	{
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
            	GUI.outputArea.append(str + "\n");
            }
        });
	}
	
	@Override
	public void run() 
	{
		if(isHost)
		{
			try {
				ServerSetup(port);
				GUI.isSending(true);
				listenLoop();
			} catch (IOException e) {
				if(e instanceof SocketException)
				{
					Log("Connection Lost.");
					return;
				}
				Log("Error running server. See console.");
				e.printStackTrace();
			} 
		}
		else
		{
			try {
				ClientSetup(host, port);
				GUI.isSending(true);
				listenLoop();
			} catch (IOException e) {
				Log("Error running client. See console.");
				e.printStackTrace();
			}
		}
	}
	
}
