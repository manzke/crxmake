package de.devsurf.chrome.extensions;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
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

public class BouncyCastleUtil {

	static{
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public static JCERSAPrivateCrtKey readCertificate(File pemFile) throws IOException{
		PEMReader reader = new PEMReader(new FileReader(pemFile));
		return (JCERSAPrivateCrtKey) reader.readObject();
	}
	
	public static PublicKey createPublicKey(JCERSAPrivateCrtKey certificate) throws InvalidKeySpecException, NoSuchAlgorithmException{
		return KeyFactory.getInstance(CrxWriter.ALGORITHMN_ENCRYPT).generatePublic(new RSAPublicKeySpec(certificate.getModulus(), certificate.getPublicExponent()));		
	}
	
	public static PrivateKey createPrivateKey(JCERSAPrivateCrtKey certificate) throws NoSuchAlgorithmException, InvalidKeySpecException{
		KeyFactory kf = KeyFactory.getInstance(CrxWriter.ALGORITHMN_ENCRYPT);
		return kf.generatePrivate(new RSAPrivateCrtKeySpec(certificate.getModulus(), certificate.getPublicExponent(), certificate.getPrivateExponent(), certificate.getPrimeP(), certificate.getPrimeQ(), certificate.getPrimeExponentP(), certificate.getPrimeExponentQ(), certificate.getCrtCoefficient()));
	}

}
