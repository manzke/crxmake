package de.devsurf.chrome.extensions;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;

import sun.security.rsa.RSAPrivateCrtKeyImpl;

public class ConsoleCrxCreator {
	public static final String ALGORITHMN_ENCRYPT = "RSA";
	
	public void create(String crxfile, String zipfile, String derfile) throws Exception{
		OutputStream out = new BufferedOutputStream(new FileOutputStream(crxfile));

		PrivateKey privateKey = createPrivateKey(getBytes(derfile));
		PublicKey publicKey = createPublicKey(privateKey);
		
		CrxWriter writer = new CrxWriter();
		writer.create(out, new BufferedInputStream(new FileInputStream(zipfile)), privateKey, publicKey);		
	}
	
	public PublicKey createPublicKey(PrivateKey privateKey) throws InvalidKeySpecException, NoSuchAlgorithmException{
		RSAPrivateCrtKeyImpl rsaPrivateKey = (RSAPrivateCrtKeyImpl)privateKey;
		
		PublicKey publicKey = KeyFactory.getInstance(ALGORITHMN_ENCRYPT).generatePublic(new RSAPublicKeySpec(rsaPrivateKey.getModulus(), rsaPrivateKey.getPublicExponent()));
		return publicKey;		
	}
	
	public PrivateKey createPrivateKey(byte[] privateKeyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException{
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

	public byte[] getBytes(String filename) throws Exception {
		File f = new File(filename);
		FileInputStream fis = new FileInputStream(f);
		DataInputStream dis = new DataInputStream(fis);
		byte[] keyBytes = new byte[(int) f.length()];
		dis.readFully(keyBytes);
		dis.close();

		return keyBytes;
	}

	public static void main(String[] args) throws Exception {
		if(!(args != null && args.length == 3)){
			System.out.println("Please pass Filename for the new CRX, Zip-File and PEM-File as Parameter.");
			System.exit(-1);
		}
		
		new ConsoleCrxCreator().create(args[0], args[1], args[2]);
	}
}
