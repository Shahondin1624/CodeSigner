package logic;

import asymetricEncryption.AsymmetricAlgorithmProvider;
import asymetricEncryption.ECProvider;
import hashing.ArgonProvider;
import hashing.HashParameters;
import hashing.HashProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class Utilities {
    protected static final String MASTER_KEY_FILE = "masterkey";
    protected static final String HASH_FILE = "system.hash";
    private final Logger logger = LoggerFactory.getLogger(Utilities.class);
    private final HashProvider hashProvider;
    private final AsymmetricAlgorithmProvider asymmetricAlgorithmProvider;

    public Utilities(HashProvider hashProvider, AsymmetricAlgorithmProvider asymmetricAlgorithmProvider) {
        this.hashProvider = hashProvider;
        this.asymmetricAlgorithmProvider = asymmetricAlgorithmProvider;
    }

    public Utilities() {
        this(new ArgonProvider(), new ECProvider());
    }

    @Deprecated
    protected static String bytesToHex(byte[] hash) {
        return Base64.getEncoder().encodeToString(hash);
    }

    @Deprecated
    protected static byte[] hexToBytes(String s) {
        return Base64.getDecoder().decode(s);
    }

    public String hashPassword(String password, HashParameters parameters) {
        return hashProvider.hash(password, parameters);
    }

    protected boolean passwordMatches(String password, String hashed, HashParameters parameters) {
        return hashProvider.hashMatches(password, hashed, parameters);
    }

    /***
     * Use %s to mask file separators as these will be supplied during runtime
     * @param name complete path after working dir
     * @return created path
     */
    public Path derivePathFromWorkingDir(String name) {
        switch (OsCheck.getOperatingSystemType()) {
            case Linux, MacOS, Other -> name = name.replaceAll("\\\\", "/");
            case Windows -> name = name.replaceAll("/", "\\\\");
        }
        return Path.of(System.getProperty("user.dir") + File.separator + name);
    }

    protected KeyPair generateKeyPair() {
        return asymmetricAlgorithmProvider.generateKeyPair();
    }

    protected void writePublicKeyToFile(PublicKey key) {
        Path keyFile = derivePathFromWorkingDir(MASTER_KEY_FILE);
        try {
            Files.write(keyFile, key.getEncoded());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    protected boolean masterKeyFileExists() {
        Path keyPath = derivePathFromWorkingDir(MASTER_KEY_FILE);
        return Files.exists(keyPath);
    }

    protected boolean hashFileExists() {
        Path hashPath = derivePathFromWorkingDir(HASH_FILE);
        return Files.exists(hashPath);
    }

    protected boolean hashesMatch(String[] paths) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        logger.debug("Reading masterkey file");
        byte[] masterKey = Files.readAllBytes(derivePathFromWorkingDir(MASTER_KEY_FILE));
        logger.debug("Attempting to hash provided files");
        PublicKey publicKey = asymmetricAlgorithmProvider.generateFromBytes(masterKey);
        byte[] hash = Files.readAllBytes(derivePathFromWorkingDir(HASH_FILE));
        return asymmetricAlgorithmProvider.verifyAuthenticity(publicKey, hash, paths);
    }

    protected void sign(String[] paths) throws NoSuchAlgorithmException, IOException {
        logger.debug("Generating key pair");
        KeyPair keyPair = generateKeyPair();
        byte[] hashedFiles = asymmetricAlgorithmProvider.sign(keyPair.getPrivate(), paths);
        logger.debug("Writing encrypted hash to file");
        Files.write(derivePathFromWorkingDir(HASH_FILE), hashedFiles);
        logger.debug("Writing masterkey file");
        writePublicKeyToFile(keyPair.getPublic());
    }
}
