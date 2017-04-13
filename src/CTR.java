import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * CTR Class to do block encryption using CTR Mode.
 *
 * @author Hasandi Patriawan, Kevin Ega Pratama, Apr 2017
 */
public class CTR {

    private static final int BLOCK_SIZE = 16;
    private static String nonceString = Util.generateRandomHexString(32);
    private static FileInputStream fi;
    private static FileOutputStream fo;
    private static BufferedReader bfKey;
    private static AES myAES = new AES();

    public void doEncryption(String pathFile, String pathKey, String pathOutput) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
        // Initiate I/O stream
        fi = new FileInputStream(pathFile);
        fo = new FileOutputStream(pathOutput);
        bfKey = new BufferedReader(new FileReader(pathKey));

        // Read the key from the file, convert it to byte[] & set AES key
        String key = bfKey.readLine();
        System.out.println("Key: " + key);
        byte[] keyByte = Util.hexToByte(key);
        myAES.setKey(keyByte);
        byte[] nonce = Util.hexToByte(nonceString);
        System.out.println("Nonce: " + nonceString);

        // Initiate ArrayList of plaintext & ciphertext result
        ArrayList<byte[]> plaintext = new ArrayList<>();
        ArrayList<byte[]> ciphertext = new ArrayList<>();

        // Read all plaintext input
        byte[] buffByte = new byte[BLOCK_SIZE];
        int readBlock = fi.read(buffByte);
        while (readBlock > 0) {
            plaintext.add(buffByte);
            buffByte = new byte[BLOCK_SIZE];
            readBlock = fi.read(buffByte);
        }

        // Calculate the residue, a number of bytes which represents the size of last block
        // from the file. For example, the residue from 36 bytes file is 4 because 36 mod 16 = 4,
        // and 36 bytes can be formed from 16+16+4 = 36 bytes.
        int fileBlockResidue = (int) (fi.getChannel().size() % 16);

        System.out.print("Plaintext (" + fi.getChannel().size() + " byte(s)): ");

        for (int i = 0; i < plaintext.size(); i++) {
            if (i == plaintext.size()-1) {
                if (fileBlockResidue != 0) {
                    byte[] tempPlaintext = Arrays.copyOfRange(plaintext.get(i), 0, fileBlockResidue);
                    System.out.print(Util.byteToHex(tempPlaintext));
                }
            } else {
                System.out.print(Util.byteToHex(plaintext.get(i)));
            }
        }

        System.out.println("\n============ ENCRYPTION START ============");

        for (int i = 0; i < plaintext.size(); i++) {
            byte[] encryptKeyNonce = myAES.encrypt(nonce); // encrypt the nonce with the key
            nonce[15] = (byte) (nonce[15]+1); // increase the counter
            System.out.println("Counter " + i);
            System.out.println("Hasil Enkripsi AES Nonce & Key: " + Util.byteToHex(encryptKeyNonce));
            byte[] ithCiphertext;

            if (i == plaintext.size()-1 && fileBlockResidue != 0) { // check the last block of the file, whether the last block length is odd, not 16 bytes
                byte[] tempPlaintext = Arrays.copyOfRange(plaintext.get(i), 0, fileBlockResidue); // remove the unused bytes
                System.out.println("Plaintext ke-" + i + ": " + Util.byteToHex(tempPlaintext));
                ithCiphertext = Util.xor(tempPlaintext, encryptKeyNonce); // XOR encrypt result with plaintext
            } else { // when the last block of the file is 16 bytes
                System.out.println("Plaintext ke-" + i + ": " + Util.byteToHex(plaintext.get(i)));
                ithCiphertext = Util.xor(plaintext.get(i), encryptKeyNonce); // XOR encrypt result with plaintext
            }
            System.out.println("Hasil Enkripsi: " + Util.byteToHex(ithCiphertext));
            System.out.println("===");
            ciphertext.add(ithCiphertext); // add the XOR result to the final ciphertext
        }

        System.out.print("Ciphertext lengkap: ");
        for (int i = 0; i < ciphertext.size(); i++) {
            System.out.print(Util.byteToHex(ciphertext.get(i)));
        }

        // Write to file
        for (int i = 0; i < ciphertext.size(); i++) {
            fo.write(ciphertext.get(i));
        }

        fi.close();
        fo.close();
        bfKey.close();
    }

    public void doDecryption(String pathFile, String pathKey, String pathOutput) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        // Initiate I/O stream
        fi = new FileInputStream(pathFile);
        fo = new FileOutputStream(pathOutput);
        bfKey = new BufferedReader(new FileReader(pathKey));

        // Read the key from the file, convert it to byte[] & set AES key
        String key = bfKey.readLine();
        System.out.println("Key: " + key);
        byte[] keyByte = Util.hexToByte(key);
        myAES.setKey(keyByte);
        byte[] nonce = Util.hexToByte(nonceString);
        System.out.println("Nonce: " + nonceString);

        // Initiate ArrayList of ciphertext & plaintext result
        ArrayList<byte[]> ciphertext = new ArrayList<>();
        ArrayList<byte[]> plaintext = new ArrayList<>();

        // Read all ciphertext input
        byte[] buffByte = new byte[BLOCK_SIZE];
        int readBlock = fi.read(buffByte);
        while (readBlock > 0) {
            ciphertext.add(buffByte);
            buffByte = new byte[BLOCK_SIZE];
            readBlock = fi.read(buffByte);
        }

        // Calculate the residue, a number of bytes which represents the size of last block
        // from the file. For example, the residue from 36 bytes file is 4 because 36 mod 16 = 4,
        // and 36 bytes can be formed from 16+16+4 = 36 bytes.
        int fileBlockResidue = (int) (fi.getChannel().size() % 16);

        System.out.print("Ciphertext (" + fi.getChannel().size() + " byte(s)): ");

        for (int i = 0; i < ciphertext.size(); i++) {
            if (i == ciphertext.size()-1) {
                if (fileBlockResidue != 0) {
                    byte[] tempCiphertext = Arrays.copyOfRange(ciphertext.get(i), 0, fileBlockResidue);
                    System.out.print(Util.byteToHex(tempCiphertext));
                }
            } else {
                System.out.print(Util.byteToHex(ciphertext.get(i)));
            }
        }

        System.out.println("\n============ DECRYPTION START ============");

        for (int i = 0; i < ciphertext.size(); i++) {
            byte[] encryptKeyNonce = myAES.encrypt(nonce); // encrypt the nonce with the key
            nonce[15] = (byte) (nonce[15]+1); // increase the counter
            System.out.println("Counter " + i);
            System.out.println("Hasil Enkripsi AES Nonce & Key: " + Util.byteToHex(encryptKeyNonce));
            byte[] ithPlaintext;

            if (i == ciphertext.size()-1 && fileBlockResidue != 0) { // check the last block of the file, whether the last block length is odd, not 16 bytes
                byte[] tempCiphertext = Arrays.copyOfRange(ciphertext.get(i), 0, fileBlockResidue); // remove the unused bytes
                System.out.println("Ciphertext ke-" + i + ": " + Util.byteToHex(tempCiphertext));
                ithPlaintext = Util.xor(tempCiphertext, encryptKeyNonce); // XOR encrypt result with plaintext
            } else { // when the last block of the file is 16 bytes
                System.out.println("Ciphertext ke-" + i + ": " + Util.byteToHex(ciphertext.get(i)));
                ithPlaintext = Util.xor(ciphertext.get(i), encryptKeyNonce); // XOR encrypt result with plaintext
            }
            System.out.println("Hasil Dekripsi: " + Util.byteToHex(ithPlaintext));
            System.out.println("===");
            plaintext.add(ithPlaintext); // add the XOR result to the final ciphertext
        }

        System.out.print("Plaintext lengkap: ");
        for (int i = 0; i < plaintext.size(); i++) {
            System.out.print(Util.byteToHex(plaintext.get(i)));
        }

        // Write to file
        for (int i = 0; i < plaintext.size(); i++) {
            fo.write(plaintext.get(i));
        }

        fi.close();
        fo.close();
        bfKey.close();
    }
}