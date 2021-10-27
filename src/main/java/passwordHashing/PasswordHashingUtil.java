package passwordHashing;

import hashing.ArgonProvider;
import hashing.HashParameters;
import hashing.HashProvider;
import logic.Utilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PasswordHashingUtil {
    private static final Logger logger = LoggerFactory.getLogger(PasswordHashingUtil.class);

    public static void main(String[] args) {
        if (args.length == 4) {
            System.out.printf("Hashed password : %s%n", new PasswordHashingUtil().hashPassword(new ArgonProvider(), args[0], parseArgs(args)));
        } else logger.warn("main arguments did not contain the correct number of arguments in the following order:"
                + " password saltLength hashLength parallelism memoryInKb, iterations");
    }

    public static HashParameters parseArgs(String[] args) {
        try {
            int parallelism = Integer.parseInt(args[1]);
            int memoryInKb = Integer.parseInt(args[2]);
            int iterations = Integer.parseInt(args[3]);
            return new HashParameters(parallelism, memoryInKb, iterations);
        } catch (RuntimeException e) {
            logger.error("Attempt to parse main method arguments failed due to a {} with message {}. Could not create Hash-Generator",
                    e.getClass().getSimpleName(), e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public String hashPassword(HashProvider provider, String password, HashParameters parameters) {
        return new Utilities(provider, null).hashPassword(password, parameters);
    }
}
