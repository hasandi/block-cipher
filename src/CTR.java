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
    private static byte[] nonceByte;
    private static FileInputStream fi;
    private static FileOutputStream fo;
    private static BufferedReader bfKey;
    private static AES myAES = new AES();
    private String nonce = Util.generateRandomHexString(32);

    public void doEncryption(String pathFile, String pathKey, String pathOutput) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
        fi = new FileInputStream(pathFile);
        fo = new FileOutputStream(pathOutput);
        bfKey = new BufferedReader(new FileReader(pathKey));

        String key = bfKey.readLine();
        System.out.println("Key: " + key);
        byte[] keyByte = Util.hexToByte(key);

        //nonce
        byte[] nonceByte = Util.hexToByte(nonce);
        myAES.setKey(keyByte);
        ArrayList<byte[]> plaintext = new ArrayList<>();
        ArrayList<byte[]> ciphertext = new ArrayList<>();


        // Read all plaintext input
        byte[] buffByte = new byte[BLOCK_SIZE];
        int readBlock = fi.read(buffByte);
        int last_len = 0;
        while (readBlock > 0) {
            plaintext.add(buffByte);
            buffByte = new byte[BLOCK_SIZE];
            readBlock = fi.read(buffByte);
        }

        int fileBlockResidue = (int) (fi.getChannel().size() % 16);

        System.out.print("Plaintext (" + fi.getChannel().size() + " byte(s): ");
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
            byte[] encryptKeyNonce = myAES.encrypt(nonceByte);
            nonceByte[15] = (byte) (nonceByte[15]+1);
            System.out.println("Counter " + i);
            System.out.println("Hasil Enkripsi AES Nonce & Key: " + Util.byteToHex(encryptKeyNonce));

            if (i == plaintext.size()-1) {
                if (fileBlockResidue != 0) {
                    byte[] tempPlaintext = Arrays.copyOfRange(plaintext.get(i), 0, fileBlockResidue);
                    System.out.println("Plaintext ke-" + i + ": " + Util.byteToHex(tempPlaintext));
                    byte[] ithCiphertext = Util.xor(tempPlaintext, encryptKeyNonce);
                    System.out.println("Hasil Enkripsi: " + Util.byteToHex(ithCiphertext));
                    System.out.println("===");
                    ciphertext.add(ithCiphertext);
                }
            } else {
                System.out.println("Plaintext ke-" + i + ": " + Util.byteToHex(plaintext.get(i)));
                byte[] ithCiphertext = Util.xor(plaintext.get(i), encryptKeyNonce);
                System.out.println("Hasil Enkripsi: " + Util.byteToHex(ithCiphertext));
                System.out.println("===");
                ciphertext.add(ithCiphertext);
            }
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

    public void doDecryption(String pathFile, String pathKey, String pathOutput) {

           }
    }
