import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.Label;
import javafx.scene.layout.BorderPane;
import javafx.scene.paint.Color;
import javafx.scene.text.Text;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


/**
 * Created by Kevin Ega Pratama(kegap) and Hasandi Patriawan on 4/13/2017.
 * Controller for the FXML file.
 */
public class Controller {

    @FXML private javafx.scene.control.MenuBar menuBar;
    @FXML private BorderPane decryptionPane;
    @FXML private BorderPane encryptionPane;
    @FXML private Label plaintextStatus;
    @FXML private Label ciphertextStatus;
    @FXML private Label keyStatus;
    @FXML private Label outputStatus;
    @FXML private Label outputDecStatus;
    @FXML private Label decryptionStatus;
    @FXML private Label encryptionStatus;

    private String pathPlaintext="";
    private String pathKey="";
    private String pathOutput="";

    private String pathCiphertext="";
    private String pathOutputDec="";

    private String error;

    /*
     * Decrypt
     * Call decryption method created at CTR.java
     * Triggered when user click decrypt button.
     */
    @FXML public void decrypt() throws Exception {
        CTR ctr = new CTR();
        try {
            //Check either ciphertext file, output file, or key file is already specified or not.
            if((pathCiphertext.equals("")) | (pathKey.equals(""))) {
                decryptionStatus.setText("Ciphertext file or key file is not specified");
                decryptionStatus.setTextFill(Color.web("red"));
            }else if(pathOutputDec == ""){
                decryptionStatus.setText("Output file is not specified");
                decryptionStatus.setTextFill(Color.web("red"));
            }else {
                //Do decryption using specified files.
                ctr.doDecryption(pathCiphertext, pathKey, pathOutputDec);
                decryptionStatus.setText("Decrypted successfully, Plaintext has been written to file."); //set status
                decryptionStatus.setTextFill(Color.web("black"));
                reset("decrypt");
            }
        }catch(Exception e){
            e.printStackTrace();
        }
    }

    /*
     * Encrypt
     * Call encryption method created at CTR.java
     * Triggered when user click encrypt button.
     */
    @FXML public void encrypt(){
        CTR ctr = new CTR();
        try {
            //Check either plaintext file, output file, or key file is already specified or not.
            if((pathPlaintext == "") | (pathKey == "")) {
                encryptionStatus.setText("Plaintext file or key file is not specified");
                encryptionStatus.setTextFill(Color.web("red"));
            }else if(pathOutput == ""){
                encryptionStatus.setText("Output file is not specified");
                encryptionStatus.setTextFill(Color.web("red"));
            }else {
                ctr.doEncryption(pathPlaintext, pathKey, pathOutput);
                encryptionStatus.setText("Status: Encrypted successfully, Ciphertext has been written to file.");
                encryptionStatus.setTextFill(Color.web("black"));
                reset("encrypt");
            }
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch(IllegalArgumentException e){
            encryptionStatus.setText("Key length must be 16 or 24 or 32 bytes"); //handles if key length is invalid/
        } catch (IOException e) {
            encryptionStatus.setText("IOException occured");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /*
    * Reset
    * @args String type
    * Reset variables used for encryption or decryption
    * Triggered after encryption or decryption process completed.
    */
    public void reset(String type){
        if(type == "encrypt") {
            pathPlaintext = "";
            pathKey = "";
            pathOutput = "";
            plaintextStatus.setText("no file selected.");
            keyStatus.setText("no file selected.");
            outputStatus.setText("no file created.");
        }else if(type == "decrypt"){
            pathCiphertext="";
            pathKey="";
            pathOutputDec="";
            ciphertextStatus.setText("no file selected.");
            keyStatus.setText("no file selected.");
            outputDecStatus.setText("no file created.");
        }
    }

    /*
    * Set Path Plaintext
    * Choose plaintext file using FileChooser class and set pathPlaintext variable with absolute path of the chosen file .
    * Triggers when open button (plaintext) clicked.
    */
    public void setPathPlaintext(){
        FileChooser fileChooser = new FileChooser();
        File file = fileChooser.showOpenDialog(new Stage());
        try {
            pathPlaintext = file.getAbsolutePath();
            plaintextStatus.setText(file.getName());
        }catch(Exception e){
        }
    }

    /*
    * Set Path Key
    * Choose key file using FileChooser class and set pathKey variable with absolute path of the chosen file.
    * Triggers when open button (key) clicked.
    */
    public void setPathKey(){
        FileChooser fileChooser = new FileChooser();
        File file = fileChooser.showOpenDialog(new Stage());
        try {
            pathKey = file.getAbsolutePath();
            keyStatus.setText(file.getName());
        }catch(Exception e){
        }
    }

    /* Set Path Output
     * Create output file using FileChooser class and set pathOutput variable with absolute path of the created file.
     * Triggers when create button (output) clicked.
     */
    public void setPathOutput(){
        FileChooser fileChooser = new FileChooser();
        File file = fileChooser.showSaveDialog(new Stage());
        try {
            pathOutput = file.getAbsolutePath();
            outputStatus.setText(file.getName());
        }catch(Exception e){
        }
    }

    /*
    * Set Path Ciphertext
    * Choose ciphertext file using FileChooser class and set pathCiphertext variable with absolute path of the chosen file .
    * Triggers when open button (ciphertext) clicked.
    */
    public void setCiphertextPath(){
        FileChooser fileChooser = new FileChooser();
        File file = fileChooser.showOpenDialog(new Stage());
        try {
            pathCiphertext = file.getAbsolutePath();
            ciphertextStatus.setText(file.getName());
        }catch(Exception e){
        }
    }

    /* Set Path Output (Decryption)
     * Create output file using FileChooser class and set pathOutputDec variable with absolute path of the created file.
     * Triggers when create button (output-decryption) clicked.
     */
    public void setPathOutputDec(){
        FileChooser fileChooser = new FileChooser();
        File file = fileChooser.showSaveDialog(new Stage());
        try{
            pathOutputDec = file.getAbsolutePath();
            outputDecStatus.setText(file.getName());
        }catch (Exception e){
        }
    }

    /* Load Decryption
     * Load decryption window (scene)
     * by creating a new scene and a new stage, setting the scene to the stage, then closing the old stage and showing the new stage
     */
    @FXML
    public void loadDecryption(ActionEvent event) throws IOException {
        Parent parent_scene= FXMLLoader.load(getClass().getResource("decryption.fxml"));
        Scene scene = new Scene(parent_scene);
        Stage newStage = (Stage) menuBar.getScene().getWindow();
        newStage.hide();
        newStage.setScene(scene);
        newStage.show();
    }


    /* Load Encryption
     * Load Encryption window (scene)
     * by creating a new scene and a new stage, setting the scene to the stage, then closing the old stage and showing the new stage
     */
    @FXML
    public void loadEncryption() throws IOException {
        Parent parent_scene = FXMLLoader.load(getClass().getResource("encryption.fxml"));
        Scene scene = new Scene(parent_scene);
        Stage newStage = (Stage) menuBar.getScene().getWindow();
        newStage.hide();
        newStage.setScene(scene);
        newStage.show();
    }

    /* Load Menu
     * Load the main menu window (scene)
     * by creating a new scene and a new stage, setting the scene to the stage, then closing the old stage and showing the new stage
     */
    @FXML
    public void loadMenu() throws IOException {
        Parent parent_scene= FXMLLoader.load(getClass().getResource("block-cipher.fxml"));
        Scene scene = new Scene(parent_scene);
        Stage newStage = (Stage) menuBar.getScene().getWindow();
        newStage.hide();
        newStage.setScene(scene);
        newStage.show();
    }
}
