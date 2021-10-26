import asymetricEncryption.RSAProvider;
import hashing.ArgonProvider;
import hashing.HashParameters;
import logic.MainWrapper;
import org.junit.jupiter.api.Assertions;

public class Test {

    public static void main(String[] args) {
        boolean aborted = true;
        MainWrapper.execute(new String[]{"src/test/java/Test.java"},
                "$argon2id$v=19$m=10240,t=10,p=1$7olGwgXHftN5yugx4nUN9g$a0XGgP+ecN1ebMxad3pximdEZDYqSe9m1r/mRImW/Go",
                new ArgonProvider(), new RSAProvider(), new HashParameters(1, 10240, 10));
        aborted = false;
        Assertions.assertFalse(aborted);
    }
}
