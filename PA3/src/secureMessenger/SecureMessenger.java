// Samuel Davidson
// https://github.com/samdamana

package secureMessenger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.*;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;

public class SecureMessenger {

	private MessengerFrame GUI;
	private BufferedReader sysReader;
	private boolean isHost = false;
	
	//Cryptography
	private RSAcryptographer rsa;
	private MessageDigest md;
	private TripleDEScryptographer TripDes;
	
	//Network
	private Socket socket;
	private byte[] buffer = new byte[4096];

	public SecureMessenger(MessengerFrame frame)
	{
		GUI = frame;
		
		Log("Building RSA cipher");
		try {
			rsa = new RSAcryptographer("Bob");
		} catch (Exception e) {
			Log("The RSA Cryptographer could not initialize.");
			return;
		}
		
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
		byte[] pubKeyPlusEncHash = EncodeDigestPlusMessage(rsa.EncodePublicKey(myKeys.getPublic()), CAkeys.getPrivate());
		socket.getOutputStream().write(pubKeyPlusEncHash);
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
		//Receive bob's public key
		int read = socket.getInputStream().read(buffer);
		byte[] secPubKey = new byte[read];
		System.arraycopy(buffer, 0, secPubKey, 0, read);
		byte[] bobPubKeyEnc = rsa.Decrypt(secPubKey, CAkeys.getPublic());
		
		//Bobs key received correctly
		
	}
	/**
	 * Outputs the message in the form [(encrypted digest) + message]
	 * The encrypted digest is the first 256 bytes
	 * @param message
	 * @param key
	 * @return output array
	 */
	private byte[] EncodeDigestPlusMessage(byte[] message, Key key)
	{
		byte[] digest = md.digest(message);
		byte[] encDigest = rsa.Encrypt(digest, key);
		byte[] output = new byte[encDigest.length + digest.length];
		System.arraycopy(digest, 0, output, 0, 256);
		System.arraycopy(message, 0, output, 256, message.length);
		return output;
	}
	
	static void Log(String str)
	{
		
		if(true)
		{
			System.err.println("Debug:\t" + str);
		}
	}

}
