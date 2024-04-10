import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Program to calculate a security property of a file, 
 * consisting of SHA3-256 (or other) digest over the file, 
 * prefixed with a shared secret
 */

/**
 * @author <insert your name here>
 *
 */
public class FileProperty {

	private static final String progName = "FileProperty"; // Name of the program
	private static final int bufSize = 512; // Almost any sensible value will work here

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		BufferedInputStream in = null; // A buffered input stream to read from
		byte[] inputBuffer = new byte[bufSize]; // A buffer for the input read from the file
		int bytesRead = 0; // Number of bytes read into the input file buffer
		byte[] messageDigest = null; // A variable for the actual digest value, as an array of bytes

		// First, check the user has provided all the required arguments, and if they
		// haven't, tell them then exit
		if (args.length != 2) {
			printUsageMessage();
			System.exit(1);
		}

		// Open the input file
		try {
			in = new BufferedInputStream(new FileInputStream(args[1]));
		} catch (FileNotFoundException e) {
			printErrorMessage("Unable to open input file: " + args[1], null);
			System.exit(1);
		}

		// Insert the correct class name for the required cryptoprimitive (1 mark, 1
		// word)
		MessageDigest digestCryptoprimitive = null;

		// Now, instantiate the required cryptoprimitive (2 marks, 5 or 6 lines)
		try {
			digestCryptoprimitive = MessageDigest.getInstance("SHA3-256");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			printErrorMessage("No such algorithm", e);
			System.exit(1);
		}

		// Now, start the hash calculation with the shared secret (1 mark, 1 line)
		digestCryptoprimitive.update(args[0].getBytes());

		// "Prime the pump" - we've got to read something before we can digest it
		// and not do anything if we read nothing.
		try {
			bytesRead = in.read(inputBuffer);
		} catch (IOException e) {
			printErrorMessage("Error reading input file " + args[1], e);
			System.exit(1);
		}

		// As long as we've read something, loop around updating the digest value
		// bytesRead will be zero if nothing was read, or -1 on EOF - treat them both
		// the same
		while (bytesRead > 0) {

			// Update the digest with the bytes that were read (2 marks, 1 line)
			digestCryptoprimitive.update(inputBuffer, 0, bytesRead);

			// And read in the next block of the file
			try {
				bytesRead = in.read(inputBuffer);
			} catch (IOException e) {
				printErrorMessage("Error reading input file " + args[1], e);
				System.exit(1);
			}
		}

		// Get the final digest value (1 mark, complete 1 line)
		messageDigest = digestCryptoprimitive.digest();

		// And print the digest value as a long hex string (1 mark, 1 line)
		System.out.println(byteArrayToHexStr(messageDigest));
	}

	/**
	 * Print an error message on stderr, optionally picking up additional detail
	 * from a passed exception
	 * 
	 * @param errMsg
	 * @param e
	 */
	private static void printErrorMessage(String errMsg, Exception e) {
		System.err.println(errMsg);
		if (e != null)
			System.err.println(e.getMessage());
	}

	/**
	 * Print a usage message
	 */
	private static void printUsageMessage() {
		System.out.println(progName + " $Revision: 1.0 $: Usage: " + progName + "<shared-secret> <infile>");
	}

	final protected static char[] hexArray = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
			'e', 'f' };
	private static String secret;

	/**
	 * Convert an array of bytes to a hexadecimal string representation Start with
	 * the top byte and work down in memory, i.e. Internet big-endian
	 * representation, as used in block symmetric cryptography
	 * 
	 * @param bytes the array to be converted
	 * @return a string of hex digits
	 */
	public static String byteArrayToHexStr(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		int v;

		for (int j = bytes.length - 1, cp = (bytes.length - 1) * 2; j >= 0; j--, cp -= 2) {
			v = bytes[j] & 0xFF;
			hexChars[cp] = hexArray[v >>> 4]; // Most Significant (Upper) Nybble
			hexChars[cp + 1] = hexArray[v & 0x0F]; // Least Significant (Lower) Nybble
		}
		return new String(hexChars);
	}

}
