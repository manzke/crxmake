package de.devsurf.chrome.extensions;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCERSAPrivateCrtKey;
import org.bouncycastle.openssl.PEMReader;

public class BouncyConsoleCrxCreator {
	public static final String ALGORITHMN_ENCRYPT = "RSA";
	
	static{
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public void create(String crxfile, String zipfile, String pemfile) throws Exception{
		PEMReader reader = new PEMReader(new FileReader(new File(pemfile)));
		JCERSAPrivateCrtKey certificate = (JCERSAPrivateCrtKey) reader.readObject();
		
		OutputStream out = new BufferedOutputStream(new FileOutputStream(crxfile));
		
		PrivateKey privateKey = createPrivateKey(certificate);
		PublicKey publicKey = createPublicKey(certificate);
		
		CrxWriter writer = new CrxWriter();
		writer.create(out, new BufferedInputStream(new FileInputStream(zipfile)), privateKey, publicKey);		
	}
	
	public PublicKey createPublicKey(JCERSAPrivateCrtKey certificate) throws InvalidKeySpecException, NoSuchAlgorithmException{
		return KeyFactory.getInstance(ALGORITHMN_ENCRYPT).generatePublic(new RSAPublicKeySpec(certificate.getModulus(), certificate.getPublicExponent()));		
	}
	
	public PrivateKey createPrivateKey(JCERSAPrivateCrtKey certificate) throws NoSuchAlgorithmException, InvalidKeySpecException{
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(new RSAPrivateCrtKeySpec(certificate.getModulus(), certificate.getPublicExponent(), certificate.getPrivateExponent(), certificate.getPrimeP(), certificate.getPrimeQ(), certificate.getPrimeExponentP(), certificate.getPrimeExponentQ(), certificate.getCrtCoefficient()));
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
		
		new BouncyConsoleCrxCreator().create(args[0], args[1], args[2]);
	}
}
