import java.io.File;
import java.io.FileWriter;
import java.nio.ByteBuffer;

public class DESkeygen {

	private final File file = new File("DESkey.txt");
	private final int KEY_LENGTH = (16 * 4);
	private final static char[] binArray = "01".toCharArray();
	private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

	public DESkeygen() {
		try {
			FileWriter fileWriter = new FileWriter(file);
			fileWriter.write("");
			StringBuffer buffer = new StringBuffer();			
			for (int i = 0; i < KEY_LENGTH; i++) {
				if ((i + 1) % 8 == 0) {
					char parity = parityBit(new String(buffer));
					buffer.append(parity);		
					//System.out.println(buffer);					
					fileWriter.append(bitsToHex(new String(buffer)));					
					fileWriter.flush();
					buffer = new StringBuffer();
				} else {
					double random = Math.random();
					int index = (int) (random * 2);
					buffer.append(binArray[index]);
				}
			}
			fileWriter.close();
			System.out.println("Key generated and saved in " + file.getName());
		} catch (Exception exp) {
			exp.printStackTrace();
		}
	}

	private String bitsToHex(String input) {
		String output = "";
		int v = Integer.parseInt(input.substring(0, 4), 2);		
		output += hexArray[v];
		v = Integer.parseInt(input.substring(4, 8), 2);		
		output += hexArray[v];		
		return output;
	}

	private char parityBit(String input) {
		char[] bits = input.toCharArray();
		int count = 0;
		for (int i = 0; i < bits.length; i++) {
			if (bits[i] == '1') {
				count++;
			}
		}
		if (count % 2 == 0) {
			return '0';
		} else {
			return '1';
		}
	}
	
	public static void main(String[] args) {
		new DESkeygen();
	}

}
