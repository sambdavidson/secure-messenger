package secureMessenger;

import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

public class TripleDEScryptographer {

	private Cipher cipher;
	private KeyGenerator keyGen;
	
	public TripleDEScryptographer()
	{
		try
		{
			cipher = Cipher.getInstance("DESede");
			keyGen = KeyGenerator.getInstance("DESede");
		}
		catch (Exception e)
		{
			//Sam is dumb
			e.printStackTrace();
			return;
		}
	}
	
	public Key GenerateKey()
	{
		return keyGen.generateKey();
	}
}
