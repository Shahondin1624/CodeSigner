package asymetricEncryption;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class RSAProvider extends AbstractProvider {
    private final String algorithm = "RSA/ECB/PKCS1Padding";
    private final String algorithmInstance;
    private final String signatureAlgorithm;
    private final Logger logger = LoggerFactory.getLogger(RSAProvider.class);
    private final String algorithmProvider;

    public RSAProvider() {
        this("RSA", "SHA256withRSA", null);
    }

    public RSAProvider(String algorithmInstance, String signatureAlgorithm, String algorithmProvider) {
        this.algorithmInstance = algorithmInstance;
        this.signatureAlgorithm = signatureAlgorithm;
        this.algorithmProvider = algorithmProvider;

    }

    public byte[] sign(PrivateKey key, String[] paths) {
        return internalSign(key, paths, signatureAlgorithm, algorithmProvider);
    }

    @Override
    public boolean verifyAuthenticity(PublicKey key, byte[] encrypted, String[] paths) {
        return internalVerificationOfAuthenticity(key, encrypted, paths, signatureAlgorithm, algorithmProvider);
    }


    @Override
    public KeyPair generateKeyPair() {
        try {
            logger.debug("Initializing KeyPairGenerator");
            KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithmInstance);
            generator.initialize(4096, SecureRandom.getInstanceStrong());
            logger.debug("Generating KeyPair");
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            logger.error("Did not find instance of {}: {}", algorithmInstance, e.getMessage());
            throw new RuntimeException(e);
        }
    }

    @Override
    public PublicKey generateFromBytes(byte[] bytes) {
        try {
            logger.debug("Initializing Key Factory to restore public key from string");
            KeyFactory kf = KeyFactory.getInstance(algorithmInstance);
            logger.debug("Regenerating public key");
            return kf.generatePublic(new X509EncodedKeySpec(bytes));
        } catch (NoSuchAlgorithmException e) {
            logger.error("Could not find signatureAlgorithm {}: {}", signatureAlgorithm, e.getMessage());
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            logger.error("Wrong key spec was used {}: {}", X509EncodedKeySpec.class.getSimpleName(), e.getMessage());
            throw new RuntimeException(e);
        }
    }
}
