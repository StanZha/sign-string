package stupid.simple;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Base64;

public class App {

    public static void main(String[] args) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, SignatureException {
        App app = new App();
        String plainText = "string of text to be signed";
        String plainTextToBeVerified = "string of text to be signed";
        // keyStorePassword and alias defined during KeyStoreFile file creation
        // KeyStoreFile file was created with keytool like this:
        // keytool -genkey -alias someAlias -keyalg RSA -validity 365 -keystore KeyStoreFile -storetype JKS
        String keyStoreEntryAlias = "someAlias";
        // difference between keyStorePassword and keyPassword: https://stackoverflow.com/a/25239918/4101334
        String keyStorePassword = "superSecretKeyStorePassword";
        String keyPassword = "evenMoreSecretKeyPasswordThatIsDifferentFromKeyStorePassword";
        // why "SHA1WithRSA"? From niels.nu: RSA is slow, so calculate SHA 256 on input first, then do signature calculation
        Signature signature = Signature.getInstance("SHA1WithRSA");

        // turn KeyStoreFile file into KeyStore instance
        KeyStore keyStore = app.loadKeyStore("KeyStoreFile", keyStorePassword);

        // initialize KeyPair object in order to use with Signature later
        KeyPair keyPair = app.createKeyPair(keyStore, keyStoreEntryAlias, keyPassword);

        // https://niels.nu/blog/2016/java-rsa.html
        // sign string
        byte[] signatureBytes = app.signStringWithPrivateKey(signature, keyPair.getPrivate(), plainText);

        System.out.printf("Signature: %s\n", Base64.getEncoder().encodeToString(signatureBytes));

        // verify string
        System.out.printf("Data is same: %s\n", app.verifySignedString(signature, keyPair.getPublic(), signatureBytes, plainTextToBeVerified));
    }

    /*
    Turn certificates file into KeyStore instance
     */
    private KeyStore loadKeyStore(String pathToKeyStoreFile, String keyStorePassword) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        FileInputStream is = new FileInputStream(pathToKeyStoreFile);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, keyStorePassword.toCharArray());
        return keystore;
    }

    /*
    Extract certificate with given alias from key store and turn it into KeyPair instance
     */
    private KeyPair createKeyPair(KeyStore keyStore, String keyStoreEntryAlias, String keyPassword) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        // https://stackoverflow.com/a/26711907/4101334
        Key key = keyStore.getKey(keyStoreEntryAlias, keyPassword.toCharArray());
        Certificate certificate = keyStore.getCertificate(keyStoreEntryAlias);
        PublicKey publicKey = certificate.getPublicKey();
        return new KeyPair(publicKey, (PrivateKey) key);
    }

    /*
    Sign string using private key
     */
    private byte[] signStringWithPrivateKey(Signature signature, PrivateKey privateKey, String plainText) throws InvalidKeyException, SignatureException {
        signature.initSign(privateKey);
        signature.update(plainText.getBytes(StandardCharsets.UTF_8));
        return signature.sign();
    }

    /*
    Verify string using public key and signature
     */
    private boolean verifySignedString(Signature signature, PublicKey publicKey, byte[] signatureBytes, String plainTextToBeVerified) throws InvalidKeyException, SignatureException {
        // use Signature instance with PublicKey to verify a string
        signature.initVerify(publicKey);
        signature.update(plainTextToBeVerified.getBytes(StandardCharsets.UTF_8));
        return signature.verify(signatureBytes);
    }
}
