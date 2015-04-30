package secureMessenger;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

// The reading and writing of keys to the file system borrows code heavily from example code found online.
// CODE EXAMPLE: http://snipplr.com/view/18368/
public class RSAcryptographer {
	
	private Cipher cipher;
	private KeyPair keys;
	public KeyPair CAkeys;
	
	//Only used if Bob... 
	public PublicKey AliceKey;
	
	public RSAcryptographer(String keyPrefix) throws Exception
	{

		try {
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		} catch (Exception e) {
			// Sam screwed up
			e.printStackTrace();
			
		} 
		
		// Read Our Public Key.
		File fileKey = new File("keys/CertificateAuthorityPublic.key");
		FileInputStream fis = new FileInputStream("keys/CertificateAuthorityPublic.key");
		byte[] encodedOurPublicKey = new byte[(int) fileKey.length()];
		fis.read(encodedOurPublicKey);
		fis.close();
 
		// Read Our Private Key.
		fileKey = new File("keys/CertificateAuthorityPrivate.key");
		fis = new FileInputStream("keys/CertificateAuthorityPrivate.key");
		byte[] encodedOurPrivateKey = new byte[(int) fileKey.length()];
		fis.read(encodedOurPrivateKey);
		fis.close();
		
		// Read CA Public Key.
		fileKey = new File("keys/CertificateAuthorityPublic.key");
		fis = new FileInputStream("keys/CertificateAuthorityPublic.key");
		byte[] encodedCAPublicKey = new byte[(int) fileKey.length()];
		fis.read(encodedCAPublicKey);
		fis.close();
 
		// Read CA Private Key.
		fileKey = new File("keys/CertificateAuthorityPrivate.key");
		fis = new FileInputStream("keys/CertificateAuthorityPrivate.key");
		byte[] encodedCAPrivateKey = new byte[(int) fileKey.length()];
		fis.read(encodedCAPrivateKey);
		fis.close();
 
		// Generate KeyPairs.
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
				encodedOurPublicKey);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
 
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
				encodedOurPrivateKey);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
 
		keys = new KeyPair(publicKey, privateKey);
		
		publicKeySpec = new X509EncodedKeySpec(
				encodedCAPublicKey);
		publicKey = keyFactory.generatePublic(publicKeySpec);
 
		privateKeySpec = new PKCS8EncodedKeySpec(
				encodedCAPrivateKey);
		privateKey = keyFactory.generatePrivate(privateKeySpec);
		
		CAkeys = new KeyPair(publicKey, privateKey);
		
		if(keyPrefix == "Bob") // We need to load Alice's public key because the assignment spec is dumb and Bob already knows Alice's key for some reason.
		{
			// Read Alice Public Key.
			fileKey = new File("keys/AlicePublic.key");
			fis = new FileInputStream("keys/AlicePublic.key");
			byte[] encodedAlicePublicKey = new byte[(int) fileKey.length()];
			fis.read(encodedAlicePublicKey);
			fis.close();
			
			publicKeySpec = new X509EncodedKeySpec(
					encodedOurPublicKey);
			AliceKey = keyFactory.generatePublic(publicKeySpec);
		}
	}
	
	public byte[] Encrypt(byte[] bytes, Key key)
	{
		try {
			cipher.init(Cipher.ENCRYPT_MODE, key);
			return cipher.doFinal(bytes);
		} catch (Exception e) {
			//Sam screwed up
			e.printStackTrace();
			return null;
		}

	}
	
	public byte[] Decrypt(byte[] bytes, Key key)
	{
		try {
			cipher.init(Cipher.DECRYPT_MODE, key);
			return cipher.doFinal(bytes);
		} catch (Exception e) {
			//Sam screwed up
			e.printStackTrace();
			return null;
		}


	}

	public byte[] EncodePublicKey(PublicKey key)
	{
		X509EncodedKeySpec x509EKS = new X509EncodedKeySpec(key.getEncoded());
		return x509EKS.getEncoded();
	}
	public PublicKey DecodePublicKey(byte[] keyEncoding)
	{
		KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (Exception e) {
			return null;
		}
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(keyEncoding);
		try {
			return keyFactory.generatePublic(publicKeySpec);
		} catch (InvalidKeySpecException e) {
			return null;
		}
	}
	public byte[] EncodePrivateKey(PrivateKey key)
	{
		PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(key.getEncoded());
		return pkcs8.getEncoded();
	}
	public PrivateKey DecodePrivateKey(byte[] keyEncoding)
	{
		KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (Exception e) {
			return null;
		}
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyEncoding);
		try {
			return keyFactory.generatePrivate(privateKeySpec);
		} catch (InvalidKeySpecException e) {
			return null;
		}
	}
	/**
	 * Generates the files for a pair of keys.
	 * Used before the program is actually runs if the keys do not already exist.
	 * 
	 * @param namePrefix Prefix of the two keys that will be appended by Public.key and Private.key
	 * @param keyLength Length of the keys in the key pair generated.
	 * @throws IOException
	 */
	static void GenerateKeyFiles(String namePrefix, int keyLength) throws IOException
	{
		KeyPairGenerator keyGen;		
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
		} catch (Exception e) {
			//Sam did something wrong.
			e.printStackTrace();
			return;
		} 
		
		keyGen.initialize(keyLength);
		KeyPair keyPair = keyGen.genKeyPair();
		
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
 
		// Store Public Key.
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
				publicKey.getEncoded());
		FileOutputStream fos = new FileOutputStream("keys/" + namePrefix + "Public.key");
		fos.write(x509EncodedKeySpec.getEncoded());
		fos.close();
 
		// Store Private Key.
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
				privateKey.getEncoded());
		fos = new FileOutputStream("keys/" + namePrefix + "Private.key");
		fos.write(pkcs8EncodedKeySpec.getEncoded());
		fos.close();
	}
	public KeyPair GetKeys()
	{
		return keys;
	}

}
