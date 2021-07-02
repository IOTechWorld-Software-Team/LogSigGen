package com.company;
import javax.swing.JFileChooser;
import java.awt.*;
import java.io.*;
import javax.swing.*;
import java.awt.event.*;
import  java.security.*;
import java.nio.charset.*;
import java.util.*;

import org.bouncycastle.openssl.*;
import org.bouncycastle.openssl.jcajce.*;
import org.json.*;

public class Main extends Component {

    private static final char[] DIGITS_LOWER =
            {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    String sha256Hex(byte[] data) {
        return new String(encodeHex(sha256Digest(data)));
    }
    byte[] sha256Digest(byte[] data) {
        return getSha256Digest().digest(data);
    }
    MessageDigest getSha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException nsae) {
            throw new IllegalArgumentException(nsae);
        }
    }

    char[] encodeHex(byte[] data) {
        int l = data.length;
        char[] out = new char[l << 1];
        int i = 0;
        for(int var5 = 0; i < l; ++i) {
            out[var5++] = DIGITS_LOWER[(240 & data[i]) >>> 4];
            out[var5++] = DIGITS_LOWER[15 & data[i]];
        }
        return out;
    }

    String createSignature(final String minifiedJson, final PrivateKey privateKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(minifiedJson.getBytes(StandardCharsets.UTF_8));
        byte[] bytesSignature = privateSignature.sign();
        return Base64.getEncoder().encodeToString(bytesSignature);
    }

    public PrivateKey getPrivateKey(String filename) throws Exception {
        String password = "";
        PEMParser pemParser = new PEMParser(new FileReader(filename));
        Object object = pemParser.readObject();
        PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyPair key;
        if (object instanceof PEMEncryptedKeyPair) {
            System.out.println("Encrypted key - we will use provided password");
            key = converter.getKeyPair(((PEMEncryptedKeyPair) object)
                    .decryptKeyPair(decProv));
        } else {
            System.out.println("Unencrypted key - no password needed "+object.getClass().getName());
            key = converter.getKeyPair((PEMKeyPair) object);
        }
        pemParser.close();
        return key.getPrivate();
    }

    public void SignLog() throws Exception {
        File PrivateKeyFile, JsonLogFile, OutPath;
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select Private Key of Drone");
        fileChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
        while(true) {
            int result = fileChooser.showOpenDialog(this);
            if (result == JFileChooser.APPROVE_OPTION) {
                PrivateKeyFile = fileChooser.getSelectedFile();
                if(!(PrivateKeyFile.getAbsolutePath().contains("pem") || PrivateKeyFile.getAbsolutePath().contains("cer"))){
                    JFrame f = new JFrame();
                    JOptionPane.showMessageDialog(f,"Invalid Private Key Format");
                    continue;
                }
                System.out.println("Selected Key file: " + PrivateKeyFile.getAbsolutePath());
                while (true) {
                    JFileChooser logChooser = new JFileChooser();
                    logChooser.setDialogTitle("Select Log to be Signed");
                    result = logChooser.showOpenDialog(this);
                    if (result == JFileChooser.APPROVE_OPTION) {
                        JsonLogFile = logChooser.getSelectedFile();
                        if (!(JsonLogFile.getAbsolutePath().contains("json"))) {
                            JFrame f = new JFrame();
                            JOptionPane.showMessageDialog(f, "Invalid Log Format");
                        }
                        else{
                            // Sign and Generate Log
                            System.out.println("Signing Log file:" + JsonLogFile.getAbsolutePath() + " Using Key:" + PrivateKeyFile.getAbsolutePath());

                            // Read the File into Json Object
                            Scanner uns_json_reader = new Scanner(JsonLogFile);
                            uns_json_reader.useDelimiter("\\Z");
                            String filedata = uns_json_reader.next();

                            JSONObject Unsigned = new JSONObject(filedata);
                            System.out.println("Signing Data :" + Unsigned.getJSONObject("flightLog").toString());

                            // Here Comes the Private Key
                            PrivateKey privateKey = getPrivateKey(PrivateKeyFile.getAbsolutePath());

                            String signatureout = createSignature(Unsigned.getJSONObject("flightLog").toString(), privateKey);
                            System.out.println("Signature Out-"+ signatureout);

                            JFrame f = new JFrame();
                            JOptionPane.showMessageDialog(f, "Log Signed Successfully");
                            return; // till now
                        }
                    }
                    else{
                        break;
                    }
                }
            }
            else{
                break;
            }
        }
    }
    public static void main(String[] args) {
        JFrame frame = new JFrame("Log Signer Verifier For NPNT Testing");
        frame.setSize(600, 200);

        JButton SignLogbutton = new JButton("Sign a Log");
        JPanel panel = new JPanel(); // the panel is not visible in output

        panel.add(SignLogbutton);
        frame.getContentPane().add(panel); // Adds Button to content pane of frame

        frame.setVisible(true);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        SignLogbutton.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    Main LogSignerVerifier = new Main();
                    LogSignerVerifier.SignLog();
                }
                catch(Exception err){
                        System.out.println("An error occurred.");
                        err.printStackTrace();
                }
            }
        });
    }
}
