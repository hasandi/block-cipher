import java.util.Random;

/**
 * Utility class for conversion between byte and hex, XOR operation between two
 * variables, and random hex string generation. This class is referencing Lawrie
 * Brown's Util class in his AES Calculator program implementation for his course.
 * (http://lpb.canb.auug.org.au/adfa/src/AEScalc/index.html).
 *
 * @author Lawrie Brown, Hasandi Patriawan, Kevin Ega Pratama, Apr 2017
 */
class Util {

    /** array mapping hex value (0-15) to corresponding hex digit (0-9a-f). */
    private static final char[] HEX_DIGITS = {
            '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'
    };

    /**
     * Utility method to convert a byte array to a hexadecimal string.
     * Each byte of the input array is converted to 2 hex symbols,
     * using the HEX_DIGITS array for the mapping.
     *
     * @param ba array of bytes to be converted into hex
     * @return hex representation of byte array
     */
    static String byteToHex(byte[] ba) {
        int length = ba.length;
        char[] buf = new char[length * 2];
        for (int i = 0, j = 0, k; i < length; ) {
            k = ba[i++];
            buf[j++] = HEX_DIGITS[(k >>> 4) & 0x0F];
            buf[j++] = HEX_DIGITS[ k        & 0x0F];
        }
        return new String(buf);
    }

    /**
     * Returns a byte array from a string of hexadecimal digits.
     *
     * @param hex string of hex characters
     * @return byte array of binary data corresponding to hex string input
     */
    static byte[] hexToByte(String hex) {
        int len = hex.length();
        byte[] buf = new byte[((len + 1) / 2)];

        int i = 0, j = 0;
        if ((len % 2) == 1)
            buf[j++] = (byte) hexDigit(hex.charAt(i++));

        while (i < len) {
            buf[j++] = (byte) ((hexDigit(hex.charAt(i++)) << 4) |
                    hexDigit(hex.charAt(i++)));
        }
        return buf;
    }

    /**
     * Returns the number from 0 to 15 corresponding to the hex digit ch.
     *
     * @param ch hex digit character (must be 0-9A-Fa-f)
     * @return   numeric equivalent of hex digit (0-15)
     */
    private static int hexDigit(char ch) {
        if (ch >= '0' && ch <= '9')
            return ch - '0';
        if (ch >= 'A' && ch <= 'F')
            return ch - 'A' + 10;
        if (ch >= 'a' && ch <= 'f')
            return ch - 'a' + 10;

        return(0);	// any other char is treated as 0
    }

    /**
     * Returns the result of XOR operation between two variables.
     *
     * @param input1 input variable 1
     * @param input2 input variable 2
     * @return XOR operation result
     */
    static byte[] xor(byte[] input1, byte[] input2) {
        byte[] tmp = new byte[input1.length];
        for (int i = 0; i < input1.length; i++) {
            tmp[i] = (byte) (input1[i] ^ input2[i]);
        }
        return tmp;
    }

    /**
     * Returns a random string in hex.
     *
     * @param numchars digits of string to be generated
     * @return generated random hex string
     */
    static String generateRandomHexString(int numchars) {
        Random r = new Random();
        StringBuilder sb = new StringBuilder();
        while(sb.length() < numchars){
            sb.append(Integer.toHexString(r.nextInt()));
        }

        return sb.toString().substring(0, numchars);
    }

}