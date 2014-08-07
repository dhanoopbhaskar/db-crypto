import org.apache.commons.codec.binary.Base64;

public class PrivateKeyCrypto {

	private String key;

	public PrivateKeyCrypto(String key) {
		this.key = key;
	}

	protected String encrypt(String plainText) {
		String cipherText = null;
		byte[] plainBytes = plainText.getBytes();
		byte[] keyBytes = key.getBytes();
		byte[] cipherBytes = null;
		if (keyBytes.length > plainBytes.length) {
			System.out.println("Key length should not exceed "
					+ "the length of plain text!");
			System.exit(0);
		} else if (keyBytes.length == plainBytes.length) {
			cipherBytes = new byte[plainBytes.length];
			for (int i = 0; i < plainBytes.length; i++) {
				cipherBytes[i] = (byte) (plainBytes[i] ^ keyBytes[i]);
			}
			cipherText = new String(Base64.encodeBase64(cipherBytes));
		} else {
			cipherBytes = new byte[plainBytes.length];
			for (int i = 0, j = 0; i < plainBytes.length; i++) {
				cipherBytes[i] = (byte) (plainBytes[i] ^ keyBytes[j]);
				j = (j + 1) % keyBytes.length;
			}
			cipherText = new String(Base64.encodeBase64(cipherBytes));
		}
		return cipherText;
	}

	protected String decrypt(String cipherText) {
		String plainText = null;
		byte[] cipherBytes = Base64.decodeBase64(cipherText.getBytes());
		byte[] keyBytes = key.getBytes();
		byte[] plainBytes = null;

		if (keyBytes.length > cipherBytes.length) {
			System.out.println("Key length should not exceed "
					+ "the length of cipher text!");
			System.exit(0);
		} else if (keyBytes.length == cipherBytes.length) {
			plainBytes = new byte[cipherBytes.length];
			for (int i = 0; i < cipherBytes.length; i++) {
				plainBytes[i] = (byte) (cipherBytes[i] ^ keyBytes[i]);
			}
			plainText = new String(plainBytes);
		} else {
			plainBytes = new byte[cipherBytes.length];
			for (int i = 0, j = 0; i < cipherBytes.length; i++) {
				plainBytes[i] = (byte) (cipherBytes[i] ^ keyBytes[j]);
				j = (j + 1) % keyBytes.length;
			}
			plainText = new String(plainBytes);
		}
		return plainText;
	}

	public static void main(String[] args) {
		PrivateKeyCrypto privateKeyCrypto = new PrivateKeyCrypto("dhanoop");
		String plainText = "malayalam";
		System.out.println("Plain Text: " + plainText);
		String cipherText = privateKeyCrypto.encrypt(plainText);
		System.out.println("After Encryption: " + cipherText);

		privateKeyCrypto = new PrivateKeyCrypto("english");
		plainText = privateKeyCrypto.decrypt(cipherText);
		System.out.println("After Decryption (wrong): " + plainText);
		
		privateKeyCrypto = new PrivateKeyCrypto("dhanoop");
		plainText = privateKeyCrypto.decrypt(cipherText);
		System.out.println("After Decryption (correct): " + plainText);
	}
}