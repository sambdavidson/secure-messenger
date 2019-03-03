// Samuel Davidson
// https://github.com/sambdavidson

package secureMessenger;

import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class TripleDEScryptographer {

	private Cipher cipher;
	private SecretKey key;
	
	public TripleDEScryptographer() throws Exception
	{
		byte [] keyBytes = new byte [24];
		new Random().nextBytes(keyBytes);
		
		cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");	//Requires padding.	
		key = new SecretKeySpec(keyBytes, "DESede");
		
	}
	public byte[] Encrypt(byte[] bytes)
	{
		IvParameterSpec iv = new IvParameterSpec(new byte[8]);
		
		try {
			cipher.init(Cipher.ENCRYPT_MODE, key, iv);
			return cipher.doFinal(bytes);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}

	}
	public byte[] Decrypt(byte[] bytes)
	{
		IvParameterSpec iv = new IvParameterSpec(new byte[8]);
		
		try {
			cipher.init(Cipher.DECRYPT_MODE, key, iv);
			return cipher.doFinal(bytes);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}

	}
	public SecretKey GetKey()
	{
		return key;
	}
	
	public void ApplyKey(byte[] encodedKey) throws Exception
	{
		key = new SecretKeySpec(encodedKey, "DESede");
		if(key == null)
		{
			throw new Exception("Key could not be generated");
		}
	}
}
