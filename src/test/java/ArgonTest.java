import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ArgonTest {
    @Test
    public void testArgonSameArgonObject() {
        Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
        String password = "test";
        String hash = argon2.hash(10, 65536, 1, password.toCharArray());
        Assertions.assertTrue(argon2.verify(hash, password.toCharArray()));
    }

    @Test
    public void testArgonDifferentArgonObject() {
        Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
        String password = "test";
        String hash = argon2.hash(10, 65536, 1, password.toCharArray());
        argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
        Assertions.assertTrue(argon2.verify(hash, password.toCharArray()));
    }
}
