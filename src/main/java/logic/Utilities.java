package logic;

import aes.CryptorUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

//TODO refactor to use byte[]s instead of strings
public class Utilities {
    private final Logger logger = LoggerFactory.getLogger(Utilities.class);
    protected static final String MASTER_KEY_FILE = "masterkey";
    protected static final String HASH_FILE = "system.hash";

    private byte[] hash(Path... paths) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        for (Path path : paths) {
            try {
                digest.update(Files.readAllBytes(path));
            } catch (IOException e) {
                logger.error("Could not read {} so the checkup is assumed to have failed", e.getMessage());
                System.exit(-1);
            }
        }
        return digest.digest();
    }

    protected static String bytesToHex(byte[] hash) {
        return Base64.getEncoder().encodeToString(hash);
    }

    protected static byte[] hexToBytes(String s) {
        return Base64.getDecoder().decode(s);
    }

    protected byte[] hashPassword(String password) throws NoSuchAlgorithmException {
        String salt = "asdfl9=)u";
        password += salt;
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        byte[] result = digest.digest(password.getBytes(StandardCharsets.UTF_8));
        for (int i = 0; i < 250; i++) {
            result = digest.digest(result);
        }
        return result;
    }

    /***
     * Use /? to mask file separators as these will be supplied during runtime
     * @param name complete path after working dir
     * @return created path
     */
    protected Path derivePathFromWorkingDir(String name) {
        return Path.of(System.getProperty("user.dir") + File.separator + name.replaceAll("&/", File.separator));
    }

    protected KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        logger.debug("Initializing KeyPairGenerator");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(4096, SecureRandom.getInstanceStrong());
        logger.debug("Generating KeyPair");
        return generator.generateKeyPair();
    }

    protected void writePublicKeyToFile(PublicKey key) {
        Path keyFile = derivePathFromWorkingDir(MASTER_KEY_FILE);
        try {
            Files.write(keyFile, key.getEncoded());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String getRelativePathPart(Path path) {
        return path.toString().replace(System.getProperty("user.dir"), "");
    }

    private Path deRelativizePath(String relativePath) {
        return Path.of(System.getProperty("user.dir") + File.separator + relativePath);
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
        byte[] fileHash = hash(Arrays.stream(paths).map(this::deRelativizePath).toArray(Path[]::new));
        byte[] retrievedHash = Files.readAllBytes(derivePathFromWorkingDir(HASH_FILE));
        logger.debug("Attempting to decrypt retrieved hash");
        PublicKey key = generateFromBytes(masterKey);
        logger.debug("Comparing retrieved and own hash");
        retrievedHash = CryptorUtil.decryptWithPublicKey(key, retrievedHash);
        return Arrays.equals(fileHash, retrievedHash);
    }

    private PublicKey generateFromBytes(byte[] bytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        logger.debug("Initializing Key Factory to restore public key from string");
        KeyFactory kf = KeyFactory.getInstance("RSA");
        logger.debug("Regenerating public key");
        return kf.generatePublic(new X509EncodedKeySpec(bytes));
    }


    protected void sign(String[] paths) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException, InvalidKeyException, IOException {
        logger.debug("Generating key pair");
        KeyPair keyPair = generateKeyPair();
        logger.debug("Generating paths from string");
        Path[] pathsArr = Arrays.stream(paths).map(this::deRelativizePath).toArray(Path[]::new);
        logger.debug("Attempting to hash provided files");
        byte[] hashedFiles = hash(pathsArr);
        logger.debug("Encrypting hash with private key");
        hashedFiles = CryptorUtil.encryptWithPrivateKey(keyPair.getPrivate(), hashedFiles);
        logger.debug("Writing encrypted hash to file");
        Files.write(derivePathFromWorkingDir(HASH_FILE), hashedFiles);
        logger.debug("Writing masterkey file");
        writePublicKeyToFile(keyPair.getPublic());
    }
}
