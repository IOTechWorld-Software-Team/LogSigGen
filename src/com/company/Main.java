//  ----------*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-**--**-*-*-*-*-*-*-*-*-*-*-*-------------------
//      Author: Yatin Khurana
//
//      IotechWorld Avigation Pvt Ltd.
//
//      Open Source Tool to generate and Verify Signature for
//      JSON Logs w.r.t new format accepted by DigitalSky and QCI Tool
//
//  ----------*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-**--**-*-*-*-*-*-*-*-*-*-*-*-------------------
package com.company;
import javax.swing.JFileChooser;
import java.awt.*;
import java.io.*;
import javax.swing.*;
import java.awt.event.*;
import  java.security.*;
import java.nio.charset.*;

import java.util.*;


import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
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

    boolean VerifySignature(final String minifiedJson, final PublicKey publickey, final byte[] in_signature)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final Signature inst = Signature.getInstance("SHA256withRSA");
        inst.initVerify(publickey);
        inst.update(minifiedJson.getBytes(StandardCharsets.UTF_8));
        return inst.verify(in_signature);
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

    public PublicKey getPublicKey(String filename) throws Exception {
        PEMParser pemParser = new PEMParser(new FileReader(filename));
        X509CertificateHolder spki = (X509CertificateHolder) pemParser.readObject();
        pemParser.close();

        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        return converter.getCertificate(spki).getPublicKey();
    }

    public void SignLog() throws Exception {
        File PrivateKeyFile, JsonLogFile;
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

                            Unsigned.put("signature", signatureout);

                            try {
                                File myObj = new File(JsonLogFile.getAbsolutePath().replace(".json", "-signed.json")); // Sorry, No JSON, Json and pee pee
                                if (myObj.createNewFile()) {
                                    System.out.println("File created: " + myObj.getName());
                                } else {
                                    System.out.println("File already exists.");
                                }
                                FileWriter outwr = new FileWriter(myObj);
                                outwr.write(Unsigned.toString());
                                outwr.close();
                                System.out.println("File saved");
                            } catch (IOException e) {
                                System.out.println("An error occurred.");
                                e.printStackTrace();
                            }

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

    public void VerifyLog() throws Exception {
        File PublicKeyFile, JsonLogFile;
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select Public Key of Drone");
        fileChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
        while(true) {
            int result = fileChooser.showOpenDialog(this);
            if (result == JFileChooser.APPROVE_OPTION) {
                PublicKeyFile = fileChooser.getSelectedFile();
                if(!(PublicKeyFile.getAbsolutePath().contains(".pem") || PublicKeyFile.getAbsolutePath().contains(".cer"))){
                    JFrame f = new JFrame();
                    JOptionPane.showMessageDialog(f,"Invalid Public Key Format");
                    continue;
                }
                System.out.println("Selected Key file: " + PublicKeyFile.getAbsolutePath());
                while (true) {
                    JFileChooser logChooser = new JFileChooser();
                    logChooser.setDialogTitle("Select Log to be Verified");
                    result = logChooser.showOpenDialog(this);
                    if (result == JFileChooser.APPROVE_OPTION) {
                        JsonLogFile = logChooser.getSelectedFile();
                        if (!(JsonLogFile.getAbsolutePath().contains("json"))) {
                            JFrame f = new JFrame();
                            JOptionPane.showMessageDialog(f, "Invalid Log Format");
                        }
                        else{
                            // Sign and Generate Log
                            System.out.println("Verifying Log file:" + JsonLogFile.getAbsolutePath() + " Using Key:" + PublicKeyFile.getAbsolutePath());

                            // Read the File into Json Object
                            Scanner uns_json_reader = new Scanner(JsonLogFile);
                            uns_json_reader.useDelimiter("\\Z");
                            String filedata = uns_json_reader.next();

                            JSONObject Unsigned = new JSONObject(filedata);
                            System.out.println("Verifying Data :" + Unsigned.getJSONObject("flightLog").toString());

                            // Here Comes the Private Key
                            PublicKey pubkey = getPublicKey(PublicKeyFile.getAbsolutePath());

                            JFrame f = new JFrame();
                            if(VerifySignature(Unsigned.getJSONObject("flightLog").toString(), pubkey, Base64.getDecoder().decode(Unsigned.getString("signature")))){
                                JOptionPane.showMessageDialog(f, "Log Signature Verified");
                            }
                            else{
                                JOptionPane.showMessageDialog(f, "Invalid Log Signature Found");
                            }
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
        frame.setSize(500, 80);

        JButton SignLogbutton = new JButton("Sign a Log");
        JButton VerifyLogbutton = new JButton("Verify a Log");
        JPanel panel = new JPanel(); // the panel is not visible in output

        panel.add(SignLogbutton);
        panel.add(VerifyLogbutton);
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
        VerifyLogbutton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    Main LogSignerVerifier = new Main();
                    LogSignerVerifier.VerifyLog();
                }
                catch(Exception err){
                    System.out.println("An error occurred.");
                    err.printStackTrace();
                }
            }
        });
    }
}
