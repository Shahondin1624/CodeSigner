package hashing;

/***
 * An interface that enables the addition of other hashing algorithms later by just implementing it
 */
public interface HashProvider {
    String hash(String password, HashParameters parameters);
    boolean hashMatches(String password, String hash, HashParameters parameters);
}
