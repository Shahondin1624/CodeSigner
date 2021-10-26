package asymetricEncryption;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.Arrays;

/***
 * A helper class that can/should be extended by any AsymmetricAlgorithmProvider to utilize predefined methods that help
 * speed up the implementation process
 */
public abstract class AbstractProvider implements AsymmetricAlgorithmProvider {
    private final Logger logger = LoggerFactory.getLogger(AbstractProvider.class);

    protected Path[] convertFromString(String[] paths) {
        logger.debug("Deriving paths");
        return Arrays.stream(paths).map(this::deRelativizePath).toArray(Path[]::new);
    }

    /***
     * Paths are supplied relative to the working directory so in order to make them absolute, the working directory has
     * to be used as a prefix
     * @return an absolute path derived from the supplied parameter
     */
    protected Path deRelativizePath(String relativePath) {
        return Path.of(System.getProperty("user.dir") + File.separator + relativePath);
    }

    protected byte[] readFile(Path path) {
        try {
            return Files.readAllBytes(path);
        } catch (IOException e) {
            logger.error("Error reading file {}", path);
            throw new RuntimeException(e);
        }
    }

    protected byte[] internalSign(PrivateKey privateKey, String[] paths, String signatureAlgorithm, String provider) {
        try {
            Signature signature;
            logger.debug("Initializing signature with algorithm");
            if (provider == null) {
                signature = Signature.getInstance(signatureAlgorithm);
            } else {
                signature = Signature.getInstance(signatureAlgorithm, provider);
            }
            logger.debug("Initializing signature with private key");
            signature.initSign(privateKey);
            updateSignatureWithFiles(paths, signature);
            logger.debug("Signing files");
            return signature.sign();
        } catch (NoSuchAlgorithmException e) {
            logger.error("Could not find signatureAlgorithm {}: {}", signatureAlgorithm, e.getMessage());
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            logger.error("While signing an exception occurred: {}", e.getMessage());
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            logger.error("A wrong private Key was provided to initialize the signature: {}", e.getMessage());
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            logger.error("Could not find algorithm provider {}: {}", provider, e.getMessage());
            throw new RuntimeException(e);
        }
    }

    protected boolean internalVerificationOfAuthenticity(PublicKey key, byte[] encrypted, String[] paths, String signatureAlgorithm, String provider) {
        try {
            Signature signature;
            logger.debug("Initializing signature with algorithm");
            if (provider == null) {
                signature = Signature.getInstance(signatureAlgorithm);
            } else {
                signature = Signature.getInstance(signatureAlgorithm, provider);
            }
            logger.debug("Initializing signature with public key");
            signature.initVerify(key);
            updateSignatureWithFiles(paths, signature);
            logger.debug("Comparing stored hash and signature generated hash");
            return signature.verify(encrypted);
        } catch (NoSuchAlgorithmException e) {
            logger.error("Could not find signatureAlgorithm {}: {}", signatureAlgorithm, e.getMessage());
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            logger.error("A wrong public Key was provided to initialize the signature: {}", e.getMessage());
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            logger.error("While signing an exception occurred: {}", e.getMessage());
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            logger.error("Could not find algorithm provider {}: {}", provider, e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private void updateSignatureWithFiles(String[] paths, Signature signature) {
        logger.debug("Updating signature with bytes from monitored files");
        Arrays.stream(convertFromString(paths)).map(this::readFile).forEach(bytes -> {
            try {
                signature.update(bytes);
            } catch (SignatureException e) {
                logger.error("While updating signature with bytes from file an exception occurred: {}", e.getMessage());
                throw new RuntimeException(e);
            }
        });
    }
}
