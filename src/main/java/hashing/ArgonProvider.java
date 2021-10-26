package hashing;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

/***
 * This class uses argon2 which has a dependency on the native library in C which has to be installed manually
 */
public class ArgonProvider implements HashProvider {
    private final Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
    @Override
    public String hash(String password, HashParameters parameters) {
        try {
            return argon2.hash(parameters.iterations(), parameters.memoryInKb(), parameters.parallelism(), password.toCharArray());
        } finally {
            argon2.wipeArray(password.toCharArray());
        }
    }

    @Override
    public boolean hashMatches(String password, String hash, HashParameters parameters) {
        try {
            return argon2.verify(hash, password.toCharArray());
        } finally {
            argon2.wipeArray(password.toCharArray());
        }
    }
}
