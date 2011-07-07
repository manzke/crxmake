package de.devsurf.chrome.extensions;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class CrxWriter {
	public static final String ALGORITHMN_ENCRYPT = "RSA";
	public static final String ALGORITHMN_SIGNATURE = "SHA1withRSA";
	public static final String CRX_BEGINNING = "Cr24";
	public static final byte[] CRX_BEGINNING_BYTES = CRX_BEGINNING.getBytes();
	public static final byte[] VERSION = new byte[]{2,0,0,0};
	
	public void create(OutputStream crxFile, InputStream content, PrivateKey privateKey, PublicKey publicKey) throws Exception{
		crxFile.write(CRX_BEGINNING_BYTES);
		crxFile.write(VERSION);

		byte[] publicKeyBytes = publicKey.getEncoded();		
		crxFile.write(new byte[]{(byte)publicKeyBytes.length,0,0,0});
		
		byte[] zip = readBytes(content, 8192, true);
		
		byte[] signature = createSignature(zip, privateKey);
		crxFile.write(new byte[]{(byte)signature.length,0,0,0});
		crxFile.write(publicKeyBytes);
		crxFile.write(signature);
		crxFile.write(zip);
		crxFile.flush();
		crxFile.close();
	}

	protected byte[] createSignature(byte[] dataToSign, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException{
		Signature signer = Signature.getInstance(ALGORITHMN_SIGNATURE);
		signer.initSign(privateKey); // PKCS#8 is preferred
		signer.update(dataToSign);
		return signer.sign();
	}

	protected byte[] readBytes(InputStream in, int bufferSize, boolean forceClose) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream(bufferSize);

		try {
			byte[] buffer = new byte[bufferSize];
			for (;;) {
				int len = in.read(buffer);
				if (len < 0) {
					break;
				}
				baos.write(buffer, 0, len);
			}
			baos.flush();
		} finally {
			if (forceClose) {
				try {
					in.close();
				} catch (Exception e) {
					// ignore
				}
				try {
					baos.close();
				} catch (Exception e) {
					// ignore
				}
			}
		}
		
		return baos.toByteArray();
	}

}
