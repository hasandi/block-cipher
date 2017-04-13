import javafx.event.ActionEvent;
import javafx.fxml.FXML;
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
 * Created by kegap on 4/13/2017.
 */
public class Controller {
    @FXML private Text hello;
    private String pathPlaintext;
    private String pathKey;
    private String pathOutput;

    private String pathPlaintextDec;
    private String pathKeyDec;
    private String pathOutputDec;


    @FXML public void decrypt() throws Exception {
        CTR ctr = new CTR();
        ctr.doDecryption(pathPlaintextDec,pathKeyDec,pathOutputDec);
    }
    @FXML public void encrypt(){
        //hello.setText("Hello World Madafaka");
        CTR ctr = new CTR();
        try {
            ctr.doEncryption(pathPlaintext,pathKey,pathOutput);
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

    public void setPathPlaintext(){
        FileChooser fileChooser = new FileChooser();
        File file = fileChooser.showOpenDialog(new Stage());
        pathPlaintext = file.getAbsolutePath();
    }

    public void setPathKey(){
        FileChooser fileChooser = new FileChooser();
        File file = fileChooser.showOpenDialog(new Stage());
        pathKey = file.getAbsolutePath();
    }

    public void setPathOutput(){
        FileChooser fileChooser = new FileChooser();
        File file = fileChooser.showSaveDialog(new Stage());
        pathOutput = file.getAbsolutePath();
    }

    public void setPathPlaintextDec(){
        FileChooser fileChooser = new FileChooser();
        File file = fileChooser.showOpenDialog(new Stage());
        pathPlaintextDec = file.getAbsolutePath();
    }

    public void setPathKeyDec(){
        FileChooser fileChooser = new FileChooser();
        File file = fileChooser.showOpenDialog(new Stage());
        pathKeyDec = file.getAbsolutePath();
    }

    public void setPathOutputDec(){
        FileChooser fileChooser = new FileChooser();
        File file = fileChooser.showSaveDialog(new Stage());
        pathOutputDec = file.getAbsolutePath();
    }
}
