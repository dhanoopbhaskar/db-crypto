import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.util.Arrays;

public class AESencrypt {
	
	private static final int BITS = 16;
	private static final int ROUNDS = 10;
	private static final int NO_OF_WORDS_IN_KEY = 44;
	private static final int KEY_LENGTH = 16;
	private static final int BLOCK_LENGTH = 16;
	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
	int[] RC = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
	Word[] Rcon = new Word[ROUNDS];	
	private byte[] word = null;
	private String mode = null;
	
	static final int[] sBox = {
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
	};
		
	static final int[] invSBox = {
		0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
		0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
		0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
		0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 
		0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 
		0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 
		0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 
		0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 
		0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 
		0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 
		0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 
		0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 
		0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 
		0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 
		0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 
		0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
	};
		
	
	public AESencrypt(String mode) {
		this.mode = mode;
		for (int i = 0 ; i < ROUNDS ; i++) {
			Rcon[i] = new Word();
			byte[] temp = new byte[4];
			temp[0] = (byte) (RC[i] & 0xff);
			temp[1] = 0;
			temp[2] = 0;
			temp[3] = 0;
			Rcon[i].setWord(temp);			
		}
		word = new byte[NO_OF_WORDS_IN_KEY];
	}
	
	/* Ref: http://www.samiam.org/galois.html */
	/* Galois Addition*/
	byte gadd(byte a, byte b) {
		return (byte) ((a ^ b) & 0xff);
	}
	/* Galois Subtraction*/
	byte gsub(byte a, byte b) {
		return (byte) ((a ^ b) & 0xff);
	}
	/* Galois Multiplication*/
	byte gmul(byte a, byte b) {
		byte p = 0;
		int counter;
		byte high_bit_set;
		byte byte0x80 = hexStringToByteArray("80")[0];
		for (counter = 0 ; counter < 8 ; counter++) {
			if((b & 0x01) == 1) {
				//System.out.println("lower bit of b is set");
				p = (byte)((p ^ a) & 0xff);
			}			
			high_bit_set = (byte) (a & 0x80);
			//printByte("high_bit_set", high_bit_set);
			a <<= 1;
			if (high_bit_set == byte0x80) {
				//System.out.println("higher bit of a is set");
				a = (byte)((a ^ 0x1b) & 0xff);
			}
			b = (byte)((b >> 1) & 0x7f);
			
			//printByte("a", a);
			//printByte("b", b);
			//printByte("p", p);
		}
		return p;
	}
	
	byte gmul(byte a, int b) {
		byte t = (byte)(b & 0xff);
		return gmul(a, t);
	}
	
	/* Key Expansion */
	private byte[] expandKey(byte[] key) throws Exception {
		//System.out.println(key.length);
		//System.out.println(bytesToHex(key));
		if(key.length != KEY_LENGTH) {
			throw new Exception("Key should be of length, 128 bits");
		}
		Word[] w = new Word[NO_OF_WORDS_IN_KEY]; 
		Word temp;
		for (int i = 0; i < 4; i++) {
			w[i] = new Word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]);	
			//System.out.println("w" + i + " = " + w[i]);
		}
		
		for (int i = 4; i < 44; i++) {
			temp = w[i-1];
			Word temp1 = new Word();
			temp1.setWord(temp.getWord());
			//System.out.println("w" + (i-1) + " = " + temp);
			if (i % 4 == 0) {
				temp1.rotWord();
				//System.out.println("Rot=" + temp1);
				temp1.subWord();
				//System.out.println("Sub=" + temp1);
				temp1 = Word.XORWords(temp1, Rcon[(i/4) - 1]);
				//System.out.println("Rcon" + temp1);
			}
			w[i] = Word.XORWords(w[i-4], temp1);
			//System.out.println("w" + i + " = " + w[i]);			
		}
		return Word.wordsToBytes(w);
	}
	
	/* Substitute Bytes */
	private byte[] subBytes(byte[] in) {
		byte[] out = new byte[BITS];
		for (int i = 0 ; i < BITS ; i++) {
			byte a = in[i];
			int row = (a >> 4) & 0x000F;
			int col = a & 0x000F;			
			out[i] = (byte) sBox[row * BITS + col];
		}
		return out;
	}
	
	/* Inverse Substitute Bytes */
	private byte[] inverseSubBytes(byte[] in) {
		byte[] out = new byte[BITS];
		for (int i = 0 ; i < BITS ; i++) {
			byte a = in[i];
			int row = (a >> 4) & 0x000F;
			int col = a & 0x000F;			
			out[i] = (byte) invSBox[row * BITS + col];
		}
		return out;
	}
	
	/* Shift Rows */
	private byte[] shiftRows(byte[] in) {
		byte[] out = new byte[BITS];
		byte[] temp = new byte[BITS];
		for (int i = 0 ; i < BITS/4 ; i++) {
			for (int j = 0 ; j < BITS/4 ; j++) {
				temp[4*j+i] = in[4*i+j];
			}
		}
		//System.out.println("temp: " + bytesToHex(temp));
		for (int i = 0 ; i < BITS/4 ; i++) {
			byte[] a = Arrays.copyOfRange(temp, (4 * i), (4 * i + 4));
			byte[] b = leftShift(a,	i);
			in[4*i] = b[0];
			in[4*i+1] = b[1];
			in[4*i+2] = b[2];
			in[4*i+3] = b[3];
		}			
		for (int i = 0 ; i < BITS/4 ; i++) {
			for (int j = 0 ; j < BITS/4 ; j++) {
				out[4*j+i] = in[4*i+j];
			}
		}
		return out;
	}
	
	private byte[] leftShift(byte[] in, int times) {
		byte[] out = new byte[4];
		out = Arrays.copyOfRange(in, 0, 4);
		for (int i = 0 ; i < times ; i++) {
			out[0] = in[1];
			out[1] = in[2];
			out[2] = in[3];
			out[3] = in[0];
			in = Arrays.copyOfRange(out, 0, 4);
		}
		return out;
	}
	
	/* Inverse Shift Rows */
	private byte[] inverseShiftRows(byte[] in) {
		byte[] out = new byte[BITS];
		byte[] temp = new byte[BITS];
		for (int i = 0 ; i < BITS/4 ; i++) {
			for (int j = 0 ; j < BITS/4 ; j++) {
				temp[4*j+i] = in[4*i+j];
			}
		}
		for (int i = 0 ; i < BITS/4 ; i++) {
			byte[] a = Arrays.copyOfRange(temp, (4 * i), (4 * i + 4));
			byte[] b = rightShift(a,	i);
			in[4 * i] = b[0];
			in[4 * i + 1] = b[1];
			in[4 * i + 2] = b[2];
			in[4 * i + 3] = b[3];
		}
		for (int i = 0 ; i < BITS/4 ; i++) {
			for (int j = 0 ; j < BITS/4 ; j++) {
				out[4*j+i] = in[4*i+j];
			}
		}
		return out;
	}
	
	private byte[] rightShift(byte[] in, int times) {
		byte[] out = new byte[4];
		out = Arrays.copyOfRange(in, 0, 4);
		for (int i = 0 ; i < times ; i++) {
			out[0] = in[3];
			out[1] = in[0];
			out[2] = in[1];
			out[3] = in[2];
			in = Arrays.copyOfRange(out, 0, 4);
		}
		return out;
	}
	
	/* Mix Columns */
	private byte[] mixColumns(byte[] in) {
		byte[] out = new byte[BITS];
		byte[] temp = new byte[BITS];		
		for (int i = 0 ; i < BITS/4 ; i++) {
			for (int j = 0 ; j < BITS/4 ; j++) {
				temp[4*j+i] = in[4*i+j];
			}
		}
		in = temp;
		for (int j = 0 ; j < BITS/4 ; j++) {
			out[4*0+j] = (byte) ((gmul(in[4*0+j], 2) 	^ gmul(in[4*1+j], 3) 	^ in[4*2+j] 			^ in[4*3+j]) 			& 0xff);
			out[4*1+j] = (byte) ((in[4*0+j] 			^ gmul(in[4*1+j], 2) 	^ gmul(in[4*2+j], 3) 	^ in[4*3+j]) 			& 0xff);
			out[4*2+j] = (byte) ((in[4*0+j] 			^ in[4*1+j] 			^ gmul(in[4*2+j], 2) 	^ gmul(in[4*3+j], 3)) 	& 0xff);
			out[4*3+j] = (byte) ((gmul(in[4*0+j], 3) 	^ in[4*1+j] 			^ in[4*2+j] 			^ gmul(in[4*3+j], 2)) 	& 0xff);
		}
		for (int i = 0 ; i < BITS/4 ; i++) {
			for (int j = 0 ; j < BITS/4 ; j++) {
				temp[4*j+i] = out[4*i+j];
			}
		}
		out = temp;
		return out;
	}
	
	/* Inverse Mix Columns */
	private byte[] inverseMixColumns(byte[] in) {
		byte[] out = new byte[BITS];
		byte[] temp = new byte[BITS];		
		for (int i = 0 ; i < BITS/4 ; i++) {
			for (int j = 0 ; j < BITS/4 ; j++) {
				temp[4*j+i] = in[4*i+j];
			}
		}
		in = temp;
		for (int j = 0 ; j < BITS/4 ; j++) {
			out[4*0+j] = (byte) ((gmul(in[4*0+j], 14) 	^ gmul(in[4*1+j], 11) 	^ gmul(in[4*2+j], 13) 	^ gmul(in[4*3+j], 9)) 	& 0xff);
			out[4*1+j] = (byte) ((gmul(in[4*0+j], 9) 	^ gmul(in[4*1+j], 14) 	^ gmul(in[4*2+j], 11) 	^ gmul(in[4*3+j], 13)) 	& 0xff);
			out[4*2+j] = (byte) ((gmul(in[4*0+j], 13) 	^ gmul(in[4*1+j], 9)	^ gmul(in[4*2+j], 14) 	^ gmul(in[4*3+j], 11)) 	& 0xff);
			out[4*3+j] = (byte) ((gmul(in[4*0+j], 11) 	^ gmul(in[4*1+j], 13)	^ gmul(in[4*2+j], 9)	^ gmul(in[4*3+j], 14)) 	& 0xff);
		}
		for (int i = 0 ; i < BITS/4 ; i++) {
			for (int j = 0 ; j < BITS/4 ; j++) {
				temp[4*j+i] = out[4*i+j];
			}
		}
		out = temp;
		return out;
	}
	
	private byte[] hexStringToByteArray(String string) {
		int length = string.length();
		int n = (int)Math.ceil((length + 1) / 2);
		byte[] result = new byte[n];		
		for (int i = length - 1; i >= 0 ; i -= 2) {	
			if (i == 0) {
				result[i / 2] = (byte) ((Character.digit('0', 16) << 4)
						+ Character.digit(string.charAt(i), 16));
			} else {
				result[i / 2] = (byte) ((Character.digit(string.charAt(i - 1), 16) << 4)
					+ Character.digit(string.charAt(i), 16));
			}
		}
		return result;
	}
	
	/* http://stackoverflow.com/questions/9655181/convert-from-byte-array-to-hex-string-in-java */
	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	
	private void printBytes(byte[] input) {				
		for (int i = 0 ; i < input.length; i++) {
			System.out.print(byteToBits(input[i]) + " ");
		}
		System.out.println();
	}
	
	private void printByte(String msg, byte input) {
		byte[] temp = new byte[1];
		temp[0] = input;
		System.out.println(msg + ": " + bytesToHex(temp));		
	}
	
	private String byteToBits(byte b) {
		StringBuffer buffer = new StringBuffer();
		for (int i = 0 ; i < 8 ; i++)
			buffer.append((int)(b >> (8-(i+1)) & 0x0001));
		return buffer.toString();
	}
	
	private byte[] getRoundKey(int round) {
		byte[] out = new byte[KEY_LENGTH];
		out = Arrays.copyOfRange(word, 16*round, 16*round+16);		
		return out;
	}
	
	public static byte[] XORBytes(byte[] in1, byte[] in2) {		
		byte[] out = new byte[in1.length];
		for (int i = 0 ; i < in1.length ; i++) {
			out[i] = (byte)((in1[i] ^ in2[i]) & 0xff);
		}			
		return out;
	}
	
	public byte[] encryptText(byte[] plainText, byte[] key) throws Exception {
		byte[] cipher = new byte[BLOCK_LENGTH];		
		this.word = expandKey(key);
		byte[] roundKey = getRoundKey(0);
		/* Round 0 */
		cipher = XORBytes(plainText, roundKey);
		//System.out.println("Round 0\n" + bytesToHex(cipher));
		/* Rounds 1 to 9*/
		for (int i = 1 ; i < 10 ; i++) {
			//System.out.println("Round " + i);
			cipher = subBytes(cipher);
			//System.out.println("SubBytes: " + bytesToHex(cipher));
			cipher = shiftRows(cipher);
			//System.out.println("ShiftRows: " + bytesToHex(cipher));
			cipher = mixColumns(cipher);
			//System.out.println("MixColumns: " + bytesToHex(cipher));
			roundKey = getRoundKey(i);
			//System.out.println("RoundKey: " + bytesToHex(roundKey));
			cipher = XORBytes(cipher, roundKey);			
			//System.out.println("CIPHER: " + bytesToHex(cipher));
		}
		/* Round 10*/
		//System.out.println("Round 10");
		cipher = subBytes(cipher);
		//System.out.println("SubBytes: " + bytesToHex(cipher));
		cipher = shiftRows(cipher);
		//System.out.println("ShiftRows: " + bytesToHex(cipher));
		roundKey = getRoundKey(10);
		//System.out.println("RoundKey: " + bytesToHex(roundKey));
		cipher = XORBytes(cipher, roundKey);
		//System.out.println("CIPHER: " + bytesToHex(cipher));
		return cipher;
	}
	
	public byte[] decryptText(byte[] cipher, byte[] key) throws Exception {
		byte[] plainText = new byte[BLOCK_LENGTH];		
		this.word = expandKey(key);
		byte[] roundKey = getRoundKey(10);
		/* Round 0 */
		plainText = XORBytes(cipher, roundKey);
		/* Rounds 1 to 9*/
		for (int i = 9 ; i > 0 ; i--) {
			plainText = inverseShiftRows(plainText);
			plainText = inverseSubBytes(plainText);
			roundKey = getRoundKey(i);
			plainText = XORBytes(plainText, roundKey);
			plainText = inverseMixColumns(plainText);
		}
		/* Round 10*/
		plainText = inverseShiftRows(plainText);
		plainText = inverseSubBytes(plainText);
		roundKey = getRoundKey(0);
		plainText = XORBytes(plainText, roundKey);
		return plainText;
	}
	
	public static void main(String[] args) throws Exception {
		try {
			if (args.length != 1) {
				System.out.println("Usage: java <classname> <mode>"
						+ "\n\t<mode> := (ECB|CBC|OFB|CFB)");
				return;
			}
			/* ECB, CBC, OFB, or CFB */			
			String mode = args[0];
			//String mode = "CFB";
			mode = mode.toUpperCase();
			AESencrypt aes = new AESencrypt(mode);	
			File keyFile = new File("AESkey.txt");
			File textFile = new File("AESplaintext.txt");
			File cipherFile = new File("AESciphertext.txt");			
			FileReader keyFileReader = new FileReader(keyFile);
			BufferedReader bufferedReader = new BufferedReader(keyFileReader);
			FileInputStream textFileInputStream = new FileInputStream(textFile);
			FileOutputStream cipherFileOutputStream = new FileOutputStream(cipherFile);
			byte[] key = new byte[(int) keyFile.length()];
			String keyString = bufferedReader.readLine();
			key = aes.hexStringToByteArray(keyString);
			byte[] message = new byte[(int) textFile.length()];
			textFileInputStream.read(message);								
			byte[] cipher = aes.encrypt(message, key);
			cipherFileOutputStream.write(cipher);
			cipherFileOutputStream.flush();
			cipherFileOutputStream.close();
			bufferedReader.close();
			textFileInputStream.close();
			System.out.println("Encryption done! Please check AESciphertext.txt for output!");
		} catch(Exception exp) {
			exp.printStackTrace();
		}
	}

	private byte[] encrypt(byte[] message, byte[] key) throws Exception {
		if (message.length < 16) {
			System.out.println("Message should be atleast 64 bits");
			System.exit(1);
		}
		if (key.length != 16) {
			System.out.println("Key should be 64 bits");
			System.exit(1);
		}
		int length = message.length;
		int n = (length + 15)/16 * 16;
		byte[] cipher = new byte[n];
		if (length == 16) {
			if (mode.equals("ECB")) {
				return encryptText(message, key);
			} else if (mode.equals("CBC")) {
				byte[] iv = getInitializationVector();
				message = XORBytes(message, iv);
				return encryptText(message, key);
			} else if (mode.equals("OFB")) {
				byte[] nounce = getNounce();
				byte[] temp = encryptText(nounce, key);
				byte[] result = XORBytes(temp, message);
				return result;
			} else if (mode.equals("CFB")) {
				
			} else {
				System.out.println("Unsupported mode of operation!");
				return null;
			}			
		}
		int i = 0;
		int k = 0;
		byte[] feedback = new byte[16];		
		if (mode.equals("CBC")) {
			feedback = getInitializationVector();
		} else if (mode.equals("OFB")) {
			feedback = getNounce();			
		} else if (mode.equals("CFB")) {
			feedback = getInitializationVectorCFB();
		}
		
		while (i < length) {
			byte[] block = new byte[16];
			byte[] result = new byte[16];
			int j = 0;
			for (; j < 16 && i < length; j++, i++) {
				block[j] = message[i];
			}
			while (j < 16) {
				/* pad with white spaces */
				block[j++] = 0x20;
			}
						
			//System.out.println("BLOCK: ");
			//printBytes(block);		
			if (mode.equals("ECB")) {
				result = encryptText(block, key);
			} else if (mode.equals("CBC")) {				
				block = XORBytes(block, feedback);
				result = encryptText(block, key);
				feedback = Arrays.copyOfRange(result, 0, 16);							
			} else if (mode.equals("OFB")) {
				result = encryptText(feedback, key);
				feedback = Arrays.copyOfRange(result, 0, 16);
				result = XORBytes(result, block);
			} else if (mode.equals("CFB")) {				
				result = encryptText(feedback, key);
				byte[] resultPart = Arrays.copyOfRange(result, 0, 8);
				byte[] blockPart = Arrays.copyOfRange(block, 0, 8);
				byte[] temp1 = XORBytes(resultPart, blockPart);
				feedback = mergeBytes(Arrays.copyOfRange(result, 8, 16), temp1);					
				resultPart = Arrays.copyOfRange(result, 8, 16);
				blockPart = Arrays.copyOfRange(block, 8, 16);
				result = encryptText(feedback, key);
				byte[] temp2 = XORBytes(resultPart, blockPart);
				feedback = mergeBytes(Arrays.copyOfRange(result, 8, 16), temp2);
				result = mergeBytes(temp1, temp2);							
			} else {
				System.out.println("Unsupported mode of operation!");
				return null;
			}			
			//System.out.println("RESULT: ");
			//printBytes(result);
			for (j = 0 ; j < 16 && k < cipher.length; j++, k++) {
				cipher[k] = result[j];
			}
		}
		return cipher;		
	}
	
	private byte[] getInitializationVector() {
		return hexStringToByteArray("247D8AC4DDB1AA739DC593821D0BC432");			
	}
	
	private byte[] getInitializationVectorCFB() {
		return hexStringToByteArray("247D8AC4DDB1AA739DC593821D0BC432");			
	}
	
	private byte[] getNounce() {
//		char[] hexArray = "0123456789ABCDEF".toCharArray();
//		String nounceStr = "";
//		for (int i = 0 ; i < 16 ; i++) {
//			double random = Math.random();
//			int index = (int) (random * 16);
//			nounceStr += hexArray[index];			
//		}
//		return hexStringToByteArray(nounceStr);
		return hexStringToByteArray("247D8AC4DDB1AA739DC593821D0BC432");
	}	

	private byte[] mergeBytes(byte[] in1, byte[] in2) {
		byte[] out = new byte[in1.length + in2.length];
		int i = 0;
		for (int j = 0 ; j < in1.length ; j++) {
			out[i++] = in1[j];
		}
		for (int j = 0 ; j < in2.length ; j++) {
			out[i++] = in2[j];
		}
		return out;
	}	
}