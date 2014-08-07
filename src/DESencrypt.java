import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.Arrays;


public class DESencrypt {
	
	private String mode = null;
	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
	
	/* Initial Permutation */
	static final int[] IP = {
		58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6,
		64, 56, 48, 40, 32, 24, 16, 8,
		57, 49, 41, 33, 25, 17,  9, 1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7
	};
	/* Inverse Initial Permutation */
	static final int[] IIP = {
		40, 8, 48, 16, 56, 24, 64, 32,
		39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30,
		37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28,
		35, 3, 43, 11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26,
		33, 1, 41,  9, 49, 17, 57, 25
	};
	/* Expansion Permutation */
	static final int[] E = {
		32,  1,  2,  3,  4,  5,
		4,  5,  6,  7,  8,  9,
		8,  9, 10, 11, 12, 13,
		12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21,
		20, 21, 22, 23, 24, 25,
		24, 25, 26, 27, 28, 29,
		28, 29, 30, 31, 32,  1
	};
	/* Permutation Function */
	static final int[] P = {
		16,  7, 20, 21,
		29, 12, 28, 17,
		1, 15, 23, 26,
		5, 18, 31, 10,
		2,  8, 24, 14,
		32, 27,  3,  9,
		19, 13, 30,  6,
		22, 11,  4, 25
	};
	/* S-Boxes*/
	static final int[] S1 = {
		14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
		 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
		 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
		15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
	};
	static final int[] S2 = {
		15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
		 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
		 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
		13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
	};
	static final int[] S3 = {
		10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
		13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
		13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
		 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
	};
	static final int[] S4 = {
		 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
		13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
		10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
		 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
	};
	static final int[] S5 = {
		 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
		14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
		 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
		11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
	};
	static final int[] S6 = {
		12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
		10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
		 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
		 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
	};
	static final int[] S7 = {
		 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
		13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
		 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
		 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
	};
	static final int[] S8 = {
		13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
		 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
		 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
		 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
	};
	/* Permuted Choice One */
	static final int[] PC1 = {
		57, 49, 41, 33, 25, 17,  9,
		 1, 58, 50, 42, 34, 26, 18,
		10,  2, 59, 51, 43, 35, 27,
		19, 11,  3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15,
		 7, 62, 54, 46, 38, 30, 22,
		14,  6, 61, 53, 45, 37, 29,
		21, 13,  5, 28, 20, 12,  4
	};
	/* Permuted Choice Two */
	static final int[] PC2 = {
		14, 17, 11, 24,  1,  5,
		 3, 28, 15,  6, 21, 10,
		23, 19, 12,  4, 26,  8,
		16,  7, 27, 20, 13,  2,
		41, 52, 31, 37, 47, 55,
		30, 40, 51, 45, 33, 48,
		44, 49, 39, 56, 34, 53,
		46, 42, 50, 36, 29, 32
	};
	/* Schedule of Left Shifts */
	static final int[] SHIFTS = {
		1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
	};
	
	public DESencrypt() {
		this.mode = "ECB";
	}
	
	public DESencrypt(String mode) {
		this.mode = mode;
	}
	
	private byte[] performXOR(byte[] one, byte[] two) {
		byte[] result = new byte[one.length];
		for (int i = 0 ; i < one.length ; i++) {
			result[i] = (byte) (one[i] ^ two[i]);
		}
		return result;
	}
	
	private byte[] permute(byte[] input, int[] mapping) {
		int byteCount = 1 + (mapping.length - 1) / 8;
		byte[] output = new byte[byteCount];
		int pos;
		
		for (int i = 0 ; i < mapping.length ; i++) {
			pos = mapping[i] - 1;
			int value = getBitFromArray(input, pos);
			setBitInArray(output, i, value);
		}		
		return output;
	}	

	private int getBitFromArray(byte[] array, int pos) {
		int value;
		int bytePos = pos / 8;
		int bitPos = pos % 8;		
		value = (array[bytePos] >> (8 - (bitPos + 1))) & 0x0001;		
		/* eg: right shift selected byte 5 times to get 3rd bit 
		 * (bitPos = 2) at rightmost position and 
		 * then AND with 0x0001*/
		return value;
	}
	
	private void setBitInArray(byte[] input, int pos, int value) {
		int bytePos = pos / 8;
		int bitPos = pos % 8;		
		byte old = input[bytePos];
		old = (byte) (((0xFF7F >> bitPos) & old) & 0x00FF);
		byte newByte = (byte) ((value << (8 - (bitPos + 1))) | old);
	    input[bytePos] = newByte;
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
	
	private String byteToBits(byte b) {
		StringBuffer buffer = new StringBuffer();
		for (int i = 0 ; i < 8 ; i++)
			buffer.append((int)(b >> (8-(i+1)) & 0x0001));
		return buffer.toString();
	}

	private byte[] getBits(byte[] input, int startPos, int length) {
		int noOfBytes = (length-1)/8 + 1;
		byte[] output = new byte[noOfBytes];
		for (int i = 0 ; i < length ; i++) {
			int value = getBitFromArray(input, startPos + i);
			setBitInArray(output, i, value);
		}
		return output;
	}	
	
	private byte[] rotateLeft(byte[] input, int step, int length) {		
		int noOfBytes = (length - 1) / 8 + 1;
		byte[] output = new byte[noOfBytes];
		for (int i = 0 ; i < length ; i++) {
			int value = getBitFromArray(input, (i + step) % length);
			setBitInArray(output, i, value);
		}
		return output;
	}
	
	private byte[] concatBits(byte[] one, int oneLength, 
			byte[] two, int twoLength) {
		int noOfBytes = (oneLength + twoLength - 1) / 8 + 1;
		byte[] output = new byte[noOfBytes];
		int i = 0, j = 0;
		for (; i < oneLength ; i++) {
			int value = getBitFromArray(one, i);
			setBitInArray(output, j, value);
			j++;
		}		
		for (i = 0 ; i < twoLength ; i++) {
			int value = getBitFromArray(two, i);
			setBitInArray(output, j, value);
			j++;
		}
		return output;
	}
	
	private byte[][] getSubKeys(byte[] masterKey) {
		int noOfSubKeys = SHIFTS.length;
		int keySize = PC1.length;
		byte[] key = permute(masterKey, PC1);
		byte[][] subKeys = new byte[noOfSubKeys][keySize];
		byte[] leftHalf = getBits(key, 0, keySize/2);
		byte[] rightHalf = getBits(key, keySize/2, keySize/2);
		for (int i = 0 ; i < noOfSubKeys ; i++) {
			leftHalf = rotateLeft(leftHalf, SHIFTS[i], keySize/2);
			rightHalf = rotateLeft(rightHalf, SHIFTS[i], keySize/2);
			byte[] subKey = concatBits(leftHalf, keySize/2, rightHalf, keySize/2);
			subKeys[i] = permute(subKey, PC2); 
		}
		return subKeys;
	}
	
	public byte[] crypt(byte[] message, byte[] key, String operation) {
		if (message.length < 8) {
			System.out.println("Message should be atleast 64 bits");
			System.exit(1);
		}
		if (key.length != 8) {
			System.out.println("Key should be 64 bits");
			System.exit(1);
		}
		int length = message.length;
		int n = (length + 7)/8 * 8;
		byte[] cipher = new byte[n];
		if (length == 8) {
			if (mode.equals("ECB")) {
				return cryptText(message, key, operation);
			} else if (mode.equals("CBC")) {
				byte[] iv = getInitializationVector();
				message = XORBytes(message, iv);
				return cryptText(message, key, operation);
			} else if (mode.equals("OFB")) {
				byte[] nounce = getNounce();
				byte[] temp = cryptText(nounce, key, operation);
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
		byte[] feedback = new byte[8];		
		if (mode.equals("CBC")) {
			feedback = getInitializationVector();
		} else if (mode.equals("OFB")) {
			feedback = getNounce();			
		} else if (mode.equals("CFB")) {
			feedback = getInitializationVectorCFB();
		}
		
		while (i < length) {
			byte[] block = new byte[8];
			byte[] result = new byte[8];
			int j = 0;
			for (; j < 8 && i < length; j++, i++) {
				block[j] = message[i];
			}
			while (j < 8) {
				/* pad with white spaces */
				block[j++] = 0x20;
			}
						
			//System.out.println("BLOCK: ");
			//printBytes(block);		
			if (mode.equals("ECB")) {
				result = cryptText(block, key, operation);
			} else if (mode.equals("CBC")) {
				if (operation.equals("encrypt")) {
					block = XORBytes(block, feedback);
					result = cryptText(block, key, operation);
					feedback = Arrays.copyOfRange(result, 0, 8);
				} else if (operation.equals("decrypt")) {
					result = cryptText(block, key, operation);
					result = XORBytes(result, feedback);
					feedback = Arrays.copyOfRange(block, 0, 8);
				}				
			} else if (mode.equals("OFB")) {
				result = cryptText(feedback, key, operation);
				feedback = Arrays.copyOfRange(result, 0, 8);
				result = XORBytes(result, block);				
			} else if (mode.equals("CFB")) {
				if (operation.equals("encrypt")) {
					result = cryptText(feedback, key, operation);
					byte[] resultPart = Arrays.copyOfRange(result, 0, 4);
					byte[] blockPart = Arrays.copyOfRange(block, 0, 4);
					byte[] temp1 = XORBytes(resultPart, blockPart);
					feedback = mergeBytes(Arrays.copyOfRange(result, 4, 8), temp1);					
					resultPart = Arrays.copyOfRange(result, 4, 8);
					blockPart = Arrays.copyOfRange(block, 4, 8);
					result = cryptText(feedback, key, operation);
					byte[] temp2 = XORBytes(resultPart, blockPart);
					feedback = mergeBytes(Arrays.copyOfRange(result, 4, 8), temp2);
					result = mergeBytes(temp1, temp2);
				} else if (operation.equals("decrypt")) {
					result = cryptText(feedback, key, "encrypt");
					byte[] resultPart = Arrays.copyOfRange(result, 0, 4);
					byte[] blockPart = Arrays.copyOfRange(block, 0, 4);
					byte[] temp1 = XORBytes(resultPart, blockPart);
					feedback = mergeBytes(Arrays.copyOfRange(result, 4, 8), blockPart);					
					resultPart = Arrays.copyOfRange(result, 4, 8);
					blockPart = Arrays.copyOfRange(block, 4, 8);
					result = cryptText(feedback, key, "encrypt");
					byte[] temp2 = XORBytes(resultPart, blockPart);
					feedback = mergeBytes(Arrays.copyOfRange(result, 4, 8), blockPart);
					result = mergeBytes(temp1, temp2);
				}				
			} else {
				System.out.println("Unsupported mode of operation!");
				return null;
			}			
			//System.out.println("RESULT: ");
			//printBytes(result);
			for (j = 0 ; j < 8 && k < cipher.length; j++, k++) {
				cipher[k] = result[j];
			}
		}
		return cipher;		
	}
	
	private byte[] getInitializationVector() {
		return hexStringToByteArray("DCBE6AE7EA5D5C61");			
	}
	
	private byte[] getInitializationVectorCFB() {
		return hexStringToByteArray("A5D5C61EFADB4351");			
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
		return hexStringToByteArray("DCBE6AE7EA5D5C61");
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
	
	public byte[] cryptText(byte[] message, byte[] key, String operation) {
		if (message.length != 8) {
			System.out.println("Message should be 64 bits");
			System.exit(1);
		}
		if (key.length != 8) {
			System.out.println("Key should be 64 bits");
			System.exit(1);
		}
		byte[] result = null;
		int blockSize = IP.length;
		byte[][] subKeys = getSubKeys(key);
		int noOfRounds = subKeys.length;
		/**
		 * Initial Permutation
		 */
		message = permute(message, IP);
		/**
		 * Split message into two halves
		 */
		byte[] leftHalf = getBits(message, 0, blockSize/2);
		byte[] rightHalf = getBits(message, blockSize/2, blockSize/2);
		for (int i = 0 ; i < noOfRounds ; i++) {
			byte[] temp = rightHalf;
			/**
			 * Expansion
			 */
			rightHalf = permute(rightHalf, E);
			/**
			 * XOR rightHalf with roundKey
			 */
			byte[] roundKey = null;
			if (operation.equalsIgnoreCase("encrypt")) {
				roundKey = subKeys[i];
			} else if (operation.equalsIgnoreCase("decrypt")) {
				roundKey = subKeys[noOfRounds - i - 1];
			} else {
				System.out.println("Unsupported operation");
				System.exit(0);
			}
			rightHalf = performXOR(rightHalf, roundKey);
			/**
			 * S-Box
			 */
			rightHalf = sBox(rightHalf);
			/**
			 * Permutation
			 */
			rightHalf = permute(rightHalf, P);
			/**
			 * XOR rightHalf with leftHalf
			 */
			rightHalf = performXOR(rightHalf, leftHalf);
			/**
			 * L(i) = R(i-1)
			 */
			leftHalf = temp;
		}
		/**
		 * 32 bit swap
		 */
		byte[] concatHalves = concatBits(rightHalf, blockSize/2, leftHalf, blockSize/2);
		/**
		 * Inverse Initial Permutation
		 */
		result = permute(concatHalves, IIP);
		return result;
	}
	
	public static byte[] XORBytes(byte[] in1, byte[] in2) {		
		byte[] out = new byte[in1.length];
		for (int i = 0 ; i < in1.length ; i++) {
			out[i] = (byte)((in1[i] ^ in2[i]) & 0xff);
		}
		return out;
	}
	
	private byte[] sBox(byte[] input) {		
		/**
		 * Split input to 6-bit blocks
		 */
		input = split(input,6);
		byte[] output = new byte[input.length/2];
		int leftHalf = 0;		
		for (int i = 0; i < input.length ; i++) {
			byte block = input[i];			
			/**
			 * row - first and last bits
			 * column - 4 bits in the middle
			 */
			int row = 2 * (block >> 7 & 0x0001) + (block >> 2 & 0x0001);
			int col = block >> 3 & 0x000F;
			int[] selectedSBox = getSBox(i);
			int rightHalf = selectedSBox[16 * row + col];
			if (i % 2 == 0) {
				leftHalf = rightHalf;
			} else {
				output[i/2] = (byte) (16 * leftHalf + rightHalf);
				leftHalf = 0;
			}
		}
		return output;
	}

	private int[] getSBox(int i) {
		switch (i) {
			case 0: return S1;
			case 1: return S2;
			case 2: return S3;
			case 3: return S4;
			case 4: return S5;
			case 5: return S6;
			case 6: return S7;
			case 7: return S8;	
			default: return null;			
		}
	}

	private byte[] split(byte[] input, int length) {
		int noOfBytes = (8 * input.length - 1) / length + 1;
		byte[] output = new byte[noOfBytes];
		for (int i = 0 ; i < noOfBytes ; i++) {
			for (int j = 0; j < length ; j++) {
				int value = getBitFromArray(input, length * i + j);				
				setBitInArray(output, 8 * i + j, value);
			}
		}
		return output;
	}

	public static void main(String[] args) {
		try {
			if (args.length != 1) {
				System.out.println("Usage: java <classname> <mode>"
						+ "\n\t<mode> := (ECB|CBC|OFB|CFB)");
				return;
			}
			/* ECB, CBC, OFB, or CFB */			
			String mode = args[0];
			mode = mode.toUpperCase();
			DESencrypt des = new DESencrypt(mode);	
			File keyFile = new File("DESkey.txt");
			File textFile = new File("DESplaintext.txt");
			File cipherFile = new File("DESciphertext.txt");			
			FileReader keyFileReader = new FileReader(keyFile);
			BufferedReader bufferedReader = new BufferedReader(keyFileReader);
			FileInputStream textFileInputStream = new FileInputStream(textFile);
			FileOutputStream cipherFileOutputStream = new FileOutputStream(cipherFile);
			byte[] key = new byte[(int) keyFile.length()];
			String keyString = bufferedReader.readLine();
			key = des.hexStringToByteArray(keyString);
			byte[] message = new byte[(int) textFile.length()];
			textFileInputStream.read(message);								
			byte[] cipher = des.crypt(message, key, "encrypt");			
			cipherFileOutputStream.write(cipher);
			cipherFileOutputStream.flush();
			cipherFileOutputStream.close();
			bufferedReader.close();
			textFileInputStream.close();
			System.out.println("Encryption done! Please check DESciphertext.txt for output!");
		} catch(Exception exp) {
			exp.printStackTrace();
		}
	}
		
}
