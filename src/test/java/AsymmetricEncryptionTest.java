import asymetricEncryption.AsymmetricAlgorithmProvider;
import asymetricEncryption.ECProvider;
import asymetricEncryption.RSAProvider;
import logic.Utilities;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PublicKey;

public class AsymmetricEncryptionTest {
    private static Path testFilePath;
    private static final String relativePathTestFile = "src/test/resources/testfile.txt";
    private final String[] paths = new String[]{relativePathTestFile};

    @BeforeAll
    public static void init() throws IOException {
        testFilePath = new Utilities().derivePathFromWorkingDir(relativePathTestFile);
        Files.writeString(testFilePath, "testfile");
    }

    @Test
    public void testPublicKeyIntegrityRSA() {
        assertPublicKeyIntegrity(new RSAProvider());
    }

    @Test
    public void testEncryptionRSA() {
        assertEncryption(new RSAProvider());
    }

    @Test
    public void testCompleteFunctionalityRSA() {
        assertCompleteFunctionality(new RSAProvider());
    }

    @Test
    public void testPublicKeyIntegrityEC() {
        assertPublicKeyIntegrity(new ECProvider());
    }

    @Test
    public void testEncryptionEC() {
        assertEncryption(new ECProvider());
    }

    @Test
    public void testCompleteFunctionalityEC() {
        assertCompleteFunctionality(new ECProvider());
    }

    private void assertPublicKeyIntegrity(AsymmetricAlgorithmProvider provider) {
        KeyPair pair = provider.generateKeyPair();
        byte[] encoded = pair.getPublic().getEncoded();
        PublicKey restored = provider.generateFromBytes(encoded);
        Assertions.assertArrayEquals(pair.getPublic().getEncoded(), restored.getEncoded());
    }

    private void assertEncryption(AsymmetricAlgorithmProvider provider) {
        KeyPair pair = provider.generateKeyPair();
        byte[] signed = provider.sign(pair.getPrivate(), paths);
        boolean verified = provider.verifyAuthenticity(pair.getPublic(), signed, paths);
        Assertions.assertTrue(verified);
    }

    private void assertCompleteFunctionality(AsymmetricAlgorithmProvider provider) {
        KeyPair keyPair = provider.generateKeyPair();
        byte[] publicKey = keyPair.getPublic().getEncoded();
        byte[] signed = provider.sign(keyPair.getPrivate(), paths);
        boolean verified = provider.verifyAuthenticity(provider.generateFromBytes(publicKey), signed, paths);
        Assertions.assertTrue(verified);
    }
}
