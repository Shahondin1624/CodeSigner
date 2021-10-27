import asymetricEncryption.ECProvider;
import hashing.ArgonProvider;
import hashing.HashParameters;
import logic.MainWrapper;
import logic.Utilities;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import passwordHashing.PasswordHashingUtil;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class WorkflowTest {
    private static String hashedPassword;
    private static final HashParameters hashParameters = new HashParameters(1, 10240, 10);
    private static Path testFilePath;
    private static final String relativePathTestFile = "src/test/resources/testfile.txt";
    private static final String[] paths = new String[]{relativePathTestFile};

    @BeforeAll
    public static void init() throws IOException {
        hashedPassword = new PasswordHashingUtil().hashPassword(new ArgonProvider(), "test", hashParameters);
        testFilePath = new Utilities().derivePathFromWorkingDir(relativePathTestFile);
        Files.writeString(testFilePath, "testfile");
        MainWrapper.execute(paths, hashedPassword, new ArgonProvider(), new ECProvider(), hashParameters);
    }

    @Test
    public void testWorkFlow() {
        boolean programDidNotAbort = false;
        MainWrapper.execute(paths, hashedPassword, new ArgonProvider(), new ECProvider(), hashParameters);
        programDidNotAbort = true;
        Assertions.assertTrue(programDidNotAbort);
    }
}
