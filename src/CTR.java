import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * CTR Class to do block encryption using CTR Mode.
 *
 * @author Hasandi Patriawan, Kevin Ega Pratama, Apr 2017
 */
class CTR {

    private static final int BLOCK_SIZE = 16;
    private static long fileSize;
    private static int fileBlockResidue;
//    private static String nonceString = Util.generateRandomHexString(32);
    private static String nonceString;
    private static FileInputStream fi;
    private static FileOutputStream fo;
    private static BufferedReader bfKey;
    private static AES myAES = new AES();
    private static boolean trace = true;

    /**
     * Method to do CTR mode block encryption.
     *
     * @param pathFile file input path
     * @param pathKey key file path
     * @param pathOutput file output path
     */
    void doEncryption(String pathFile, String pathKey, String pathOutput) throws Exception {
        // Initiate I/O stream
        initIOStream(pathFile, pathKey, pathOutput);

        // Get the file size in bytes
        fileSize = fi.getChannel().size() % BLOCK_SIZE;

        // Calculate the residue, a number of bytes which represents the size of last block
        // from the file. For example, the residue from 36 bytes file is 4 because 36 mod 16 = 4,
        // and 36 bytes can be formed from 16+16+4 = 36 bytes.
        fileBlockResidue = (int) (fileSize % 16);

        // Initiate ArrayList of plaintext & ciphertext result
        ArrayList<byte[]> plaintext = new ArrayList<>();
        ArrayList<byte[]> ciphertext = new ArrayList<>();


        // Read all plaintext input
        readFileBytes(plaintext);

        if (trace) {
            System.out.print("Plaintext (" + fi.getChannel().size() + " byte(s)): ");
            printFileBytes(plaintext);
        }

        // Read the key from the file, convert it to byte[] & set AES key
        String key = bfKey.readLine();
        byte[] keyByte = Util.hexToByte(key);
        myAES.setKey(keyByte);
        setNonceString(keyByte);
        byte[] nonce = Util.hexToByte(nonceString);

        if (trace) {
            System.out.println("Key: " + key);
            System.out.println("Nonce: " + nonceString);
            System.out.println("\n============ ENCRYPTION START ============");
        }

        for (int i = 0; i < plaintext.size(); i++) {
            byte[] encryptKeyNonce = AES.encrypt(nonce); // encrypt the nonce with the key
            nonce[15] = (byte) (nonce[15]+1); // increase the counter
            byte[] ithCiphertext;

            if (trace) {
                System.out.println("Counter " + i);
                System.out.println("Hasil Enkripsi AES Nonce & Key: " + Util.byteToHex(encryptKeyNonce));
            }

            if (i == plaintext.size()-1 && fileBlockResidue != 0) { // check the last block of the file, whether the last block length is odd, not 16 bytes
                byte[] tempPlaintext = Arrays.copyOfRange(plaintext.get(i), 0, fileBlockResidue); // remove the unused bytes
                ithCiphertext = Util.xor(tempPlaintext, encryptKeyNonce); // XOR encrypt result with plaintext

                if (trace)
                    System.out.println("Plaintext ke-" + i + ": " + Util.byteToHex(tempPlaintext));

            } else { // when the last block of the file is 16 bytes
                ithCiphertext = Util.xor(plaintext.get(i), encryptKeyNonce); // XOR encrypt result with plaintext

                if (trace)
                    System.out.println("Plaintext ke-" + i + ": " + Util.byteToHex(plaintext.get(i)));
            }

            ciphertext.add(ithCiphertext); // add the XOR result to the final ciphertext

            if (trace) {
                System.out.println("Hasil Enkripsi: " + Util.byteToHex(ithCiphertext));
                System.out.println("===");
            }
        }

        if (trace) {
            System.out.print("Ciphertext lengkap: ");
            for (byte[] aCiphertext : ciphertext) {
                System.out.print(Util.byteToHex(aCiphertext));
            }
            System.out.println();
        }

        writeToFile(ciphertext);
        closeIOStream();
    }

    /**
     * Method to do the CTR mode block decryption.
     *
     * @param pathFile file input path
     * @param pathKey key file path
     * @param pathOutput file output path
     */
    void doDecryption(String pathFile, String pathKey, String pathOutput) throws Exception {
        // Initiate I/O stream
        initIOStream(pathFile, pathKey, pathOutput);

        // Get the file size in bytes
        fileSize = fi.getChannel().size() % BLOCK_SIZE;

        // Calculate the residue, a number of bytes which represents the size of last block
        // from the file. For example, the residue from 36 bytes file is 4 because 36 mod 16 = 4,
        // and 36 bytes can be formed from 16+16+4 = 36 bytes.
        fileBlockResidue = (int) (fileSize % 16);

        // Initiate ArrayList of ciphertext & plaintext result
        ArrayList<byte[]> ciphertext = new ArrayList<>();
        ArrayList<byte[]> plaintext = new ArrayList<>();

        // Read all ciphertext input
        readFileBytes(ciphertext);

        if (trace) {
            System.out.print("Ciphertext (" + fi.getChannel().size() + " byte(s)): ");
            printFileBytes(ciphertext);
        }

        // Read the key from the file, convert it to byte[] & set AES key
        String key = bfKey.readLine();
        byte[] keyByte = Util.hexToByte(key);
        myAES.setKey(keyByte);
        setNonceString(keyByte);
        byte[] nonce = Util.hexToByte(nonceString);

        if (trace) {
            System.out.println("Key: " + key);
            System.out.println("Nonce: " + nonceString);
            System.out.println("\n============ DECRYPTION START ============");
        }

        for (int i = 0; i < ciphertext.size(); i++) {
            byte[] encryptKeyNonce = AES.encrypt(nonce); // encrypt the nonce with the key
            nonce[15] = (byte) (nonce[15]+1); // increase the counter
            byte[] ithPlaintext;

            if (trace) {
                System.out.println("Counter " + i);
                System.out.println("Hasil Enkripsi AES Nonce & Key: " + Util.byteToHex(encryptKeyNonce));
            }

            if (i == ciphertext.size()-1 && fileBlockResidue != 0) { // check the last block of the file, whether the last block length is odd, not 16 bytes
                byte[] tempCiphertext = Arrays.copyOfRange(ciphertext.get(i), 0, fileBlockResidue); // remove the unused bytes
                ithPlaintext = Util.xor(tempCiphertext, encryptKeyNonce); // XOR encrypt result with ciphertext

                if (trace)
                    System.out.println("Ciphertext ke-" + i + ": " + Util.byteToHex(tempCiphertext));
            } else { // when the last block of the file is 16 bytes
                ithPlaintext = Util.xor(ciphertext.get(i), encryptKeyNonce); // XOR encrypt result with ciphertext

                if (trace)
                    System.out.println("Ciphertext ke-" + i + ": " + Util.byteToHex(ciphertext.get(i)));
            }

            plaintext.add(ithPlaintext); // add the XOR result to the final plaintext

            if (trace) {
                System.out.println("Hasil Dekripsi: " + Util.byteToHex(ithPlaintext));
                System.out.println("===");
            }
        }

        if (trace) {
            System.out.print("Plaintext lengkap: ");
            for (byte[] aPlaintext : plaintext) {
                System.out.print(Util.byteToHex(aPlaintext));
            }
        }

        writeToFile(plaintext);
        closeIOStream();
    }

    static void setNonceString(byte[] key) {
        if (key.length == 16) {
            nonceString = "12345678123456781234567812345678";
        } else if (key.length == 24) {
            nonceString = "123456781234567812345678123456781234567812345678";
        } else {
            nonceString = "1234567812345678123456781234567812345678123456781234567812345678";
        }
    }

    /**
     * Method to initiate the file input/output stream.
     *
     * @param pathFile file input path
     * @param pathKey key file path
     * @param pathOutput file output path
     */
    private static void initIOStream(String pathFile, String pathKey, String pathOutput) throws FileNotFoundException {
        fi = new FileInputStream(pathFile);
        fo = new FileOutputStream(pathOutput);
        bfKey = new BufferedReader(new FileReader(pathKey));
    }

    /**
     * Method to read file bytes from input stream and store it in an array list.
     *
     * @param file array list where the file bytes stored
     */
    private static void readFileBytes(ArrayList<byte[]> file) throws IOException {
        byte[] buffByte = new byte[BLOCK_SIZE];
        int readBlock = fi.read(buffByte);
        while (readBlock > 0) {
            file.add(buffByte);
            buffByte = new byte[BLOCK_SIZE];
            readBlock = fi.read(buffByte);
        }
    }

    /**
     * Method to print the file bytes in hex.
     *
     * @param file file in form of array list to be printed
     */
    private static void printFileBytes(ArrayList<byte[]> file) {
        for (int i = 0; i < file.size(); i++) {
            if (i == file.size()-1) {
                if (fileBlockResidue != 0) {
                    byte[] tempCiphertext = Arrays.copyOfRange(file.get(i), 0, fileBlockResidue);
                    System.out.print(Util.byteToHex(tempCiphertext));
                }
            } else {
                System.out.print(Util.byteToHex(file.get(i)));
            }
        }
    }

    /**
     * Method to write the data in bytes to file.
     *
     * @param bytes array list of bytes array to be written to file
     */
    private static void writeToFile(ArrayList<byte[]> bytes) throws IOException {
        for (byte[] aByte : bytes) {
            fo.write(aByte);
        }
    }

    /**
     * Method to close the file input/output stream.
     */
    private static void closeIOStream() throws IOException {
        fi.close();
        fo.close();
        bfKey.close();
    }
}