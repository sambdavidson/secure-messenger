package secureMessenger;

import java.io.File;
import java.io.FileInputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;


public class RSAcryptographer {
	
	private Cipher cipher;
	private KeyPairGenerator keyGen;
	private KeyPair keys;
	public KeyPair CAkeys;
	
	public RSAcryptographer() throws Exception
	{
		try {
			cipher = Cipher.getInstance("RSA");
			keyGen = KeyPairGenerator.getInstance("RSA");
		} catch (Exception e) {
			//Sam did something wrong.
			e.printStackTrace();
			return;
		} 
		keyGen.initialize(2048);
		keys = keyGen.genKeyPair();
		
		// THIS NEXT CA LOADING SECTION HEAVILY BORROWS CODE FROM EXAMPLE FOUND ONLINE
		// CODE EXAMPLE: http://snipplr.com/view/18368/
		
		// Read Public Key.
		File filePublicKey = new File("keys/CertificateAuthorityPublic.key");
		FileInputStream fis = new FileInputStream("keys/CertificateAuthorityPublic.key");
		byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
		fis.read(encodedPublicKey);
		fis.close();
 
		// Read Private Key.
		File filePrivateKey = new File("keys/CertificateAuthorityPrivate.key");
		fis = new FileInputStream("keys/CertificateAuthorityPrivate.key");
		byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
		fis.read(encodedPrivateKey);
		fis.close();
 
		// Generate KeyPair.
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
				encodedPublicKey);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
 
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
				encodedPrivateKey);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
 
		CAkeys = new KeyPair(publicKey, privateKey);
		// END OF BORROWED CODE SECTION
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
	public KeyPair GetKeys()
	{
		return keys;
	}

}
