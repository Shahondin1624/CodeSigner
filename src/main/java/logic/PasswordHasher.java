package logic;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;

public class PasswordHasher {
    private static final Logger logger = LoggerFactory.getLogger(PasswordHasher.class);

    public static void main(String[] args) throws NoSuchAlgorithmException {
        if (args.length == 1) {
            Utilities util = new Utilities();
            System.out.printf("Hashed password : %s%n", Utilities.bytesToHex(util.hashPassword(args[0])));
        } else logger.warn("main arguments did not contain exactly one password");
    }
}
