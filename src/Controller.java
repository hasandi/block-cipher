import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.Label;
import javafx.scene.layout.BorderPane;
import javafx.scene.text.Text;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by kegap on 4/13/2017.
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

    private String pathPlaintext;
    private String pathKey;
    private String pathOutput;

    private String pathCiphertext;
    private String pathOutputDec;


    @FXML public void decrypt() throws Exception {
        CTR ctr = new CTR();
        try {
            ctr.doDecryption(pathCiphertext, pathKey, pathOutputDec);
            decryptionStatus.setText("Decrypted successfully, Plaintext has been written to file.");
            reset("decrypt");
        }catch(Exception e){
            e.printStackTrace();
        }
        }
    @FXML public void encrypt(){
        //hello.setText("Hello World Madafaka");
        CTR ctr = new CTR();
        try {
            ctr.doEncryption(pathPlaintext,pathKey,pathOutput);
            encryptionStatus.setText("Status: Encrypted successfully, Ciphertext has been written to file.");
            reset("encrypt");
        } catch (InvalidKeyException e) {
            e.printStackTrace();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void reset(String type){
        if(type == "encrypt") {
            pathPlaintext = "";
            pathKey = "";
            pathOutput = "";
            plaintextStatus.setText("no file selected.");
            keyStatus.setText("no file selected.");
            outputStatus.setText("no file created.");
        }

        if(type == "decrypt"){
            pathCiphertext="";
            pathKey="";
            pathOutputDec="";
            ciphertextStatus.setText("no file selected.");
            keyStatus.setText("no file selected.");
            outputDecStatus.setText("no file created.");

        }
    }

    public void setPathPlaintext(){
        FileChooser fileChooser = new FileChooser();
        File file = fileChooser.showOpenDialog(new Stage());
        if(!file.equals(null)){
            pathPlaintext = file.getAbsolutePath();
            plaintextStatus.setText(file.getName());
        }
    }

    public void setPathKey(){
        FileChooser fileChooser = new FileChooser();
        File file = fileChooser.showOpenDialog(new Stage());
        if(!file.equals(null)) {
            pathKey = file.getAbsolutePath();
            keyStatus.setText(file.getName());
        }
    }

    public void setPathOutput(){
        FileChooser fileChooser = new FileChooser();
        File file = fileChooser.showSaveDialog(new Stage());
        if(!file.equals(null)) {
            pathOutput = file.getAbsolutePath();
            outputStatus.setText(file.getName());
        }
    }

    public void setCiphertextPath(){
        FileChooser fileChooser = new FileChooser();
        File file = fileChooser.showOpenDialog(new Stage());
        if(!file.equals(null)) {
            file.getAbsolutePath();
            ciphertextStatus.setText(file.getName());
        }
    }

    public void setPathOutputDec(){
        FileChooser fileChooser = new FileChooser();
        File file = fileChooser.showSaveDialog(new Stage());
        if(!file.equals(null)) {
            pathOutputDec = file.getAbsolutePath();
            outputDecStatus.setText(file.getName());
        }
    }

    @FXML
    public void loadDecryption(ActionEvent event) throws IOException {
        Parent parent_scene= FXMLLoader.load(getClass().getResource("decryption.fxml"));
        Scene scene = new Scene(parent_scene);
        Stage newStage = (Stage) menuBar.getScene().getWindow();
        newStage.hide();
        newStage.setScene(scene);
        newStage.show();
    }

    @FXML
    public void loadEncryption() throws IOException {
        Parent parent_scene = FXMLLoader.load(getClass().getResource("encryption.fxml"));
        Scene scene = new Scene(parent_scene);
        Stage newStage = (Stage) menuBar.getScene().getWindow();
        newStage.hide();
        newStage.setScene(scene);
        newStage.show();
    }

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
