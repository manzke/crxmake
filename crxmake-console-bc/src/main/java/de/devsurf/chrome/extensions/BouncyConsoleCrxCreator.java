package de.devsurf.chrome.extensions;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.jce.provider.JCERSAPrivateCrtKey;

public class BouncyConsoleCrxCreator {
	public static final String ALGORITHMN_ENCRYPT = "RSA";
	
	public void create(String crxfile, String zipfile, String pemfile) throws Exception{
		JCERSAPrivateCrtKey certificate = BouncyCastleUtil.readCertificate(new File(pemfile));
		
		OutputStream out = new BufferedOutputStream(new FileOutputStream(crxfile));
		
		PrivateKey privateKey = BouncyCastleUtil.createPrivateKey(certificate);
		PublicKey publicKey = BouncyCastleUtil.createPublicKey(certificate);
		
		CrxWriter writer = new CrxWriter();
		writer.create(out, new BufferedInputStream(new FileInputStream(zipfile)), privateKey, publicKey);		
	}

	public static void main(String[] args) throws Exception {
		if(!(args != null && args.length == 3)){
			System.out.println("Please pass Filename for the new CRX, Zip-File and PEM-File as Parameter.");
			System.exit(-1);
		}
		
		new BouncyConsoleCrxCreator().create(args[0], args[1], args[2]);
	}
}
