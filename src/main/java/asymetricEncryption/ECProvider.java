package asymetricEncryption;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class ECProvider extends AbstractProvider {
    private final Logger logger = LoggerFactory.getLogger(ECProvider.class);
    private final String algorithmInstance;
    private final String algorithmProvider;
    private final String parameterSpec;
    private final String signatureInstance;

    public ECProvider() {
        this("EC", null, "secp256r1", "SHA256withECDSA");
    }

    public ECProvider(String algorithmInstance, String algorithmProvider, String parameterSpec, String signatureInstance) {
        this.algorithmInstance = algorithmInstance;
        this.algorithmProvider = algorithmProvider;
        this.parameterSpec = parameterSpec;
        this.signatureInstance = signatureInstance;
    }

    @Override
    public byte[] sign(PrivateKey key, String[] paths) {
        return internalSign(key, paths, signatureInstance, algorithmProvider);
    }

    @Override
    public boolean verifyAuthenticity(PublicKey key, byte[] encrypted, String[] paths) {
        return internalVerificationOfAuthenticity(key, encrypted, paths, signatureInstance, algorithmProvider);
    }


    @Override
    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator;
            if (algorithmProvider == null) {
                generator = KeyPairGenerator.getInstance(algorithmInstance);
            } else {
                generator = KeyPairGenerator.getInstance(algorithmInstance, algorithmProvider);
            }
            ECGenParameterSpec ecsp = new ECGenParameterSpec(parameterSpec);
            generator.initialize(ecsp);
            return generator.genKeyPair();
        } catch (InvalidAlgorithmParameterException e) {
            logger.error("Could not parse ECGenParameterSpec {}: {}", parameterSpec, e.getMessage());
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            logger.error("Could not find {} algorithm: {}", algorithmInstance, e.getMessage());
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            logger.error("Could not find provider {}: {}", algorithmProvider, e.getMessage());
            throw new RuntimeException(e);
        }
    }

    @Override
    public PublicKey generateFromBytes(byte[] bytes) {
        try {
            KeyFactory keyFactory;
            if (algorithmProvider == null) {
                keyFactory = KeyFactory.getInstance(algorithmInstance);
            } else {
                keyFactory = KeyFactory.getInstance(algorithmInstance, algorithmProvider);
            }
            return keyFactory.generatePublic(new X509EncodedKeySpec(bytes));
        } catch (NoSuchAlgorithmException e) {
            logger.error("Could not find signatureAlgorithm {}: {}", algorithmInstance, e.getMessage());
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            logger.error("Wrong key spec was used {}: {}", X509EncodedKeySpec.class.getSimpleName(), e.getMessage());
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            logger.error("Could not find provider {}: {}", algorithmProvider, e.getMessage());
            throw new RuntimeException(e);
        }
    }
}
