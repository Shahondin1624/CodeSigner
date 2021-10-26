package asymetricEncryption;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/***
 * A very generic interface that enables the addition of other asymmetric encryption algorithms. {@link AbstractProvider}
 * provides generic methods to speed up implementations, so any new Provider should extend it, unless the provided methods
 * do not fit the requirements.
 */
public interface AsymmetricAlgorithmProvider {

    /***
     * Creates an encrypted checksum of the provided files (paths)
     * @param key used to encrypt the hash of these files
     * @param paths to read byte values from all files
     * @return the encrypted checksum as byte[]
     */
    byte[] sign(PrivateKey key, String[] paths);

    /***
     * Determines whether the monitored files have been changed since the last signing
     * @param key used to decrypt the checksum
     * @param encrypted checksum of the monitored files that has been created during the last signing process
     * @param paths to read byte values from all files
     * @return whether the monitored files have been changed since the last signing
     */
    boolean verifyAuthenticity(PublicKey key, byte[] encrypted, String[] paths);

    /***
     * The process of signing/verifying requires an asymmetric key pair (private key to encrypt checksum, public to decrypt
     * for comparison with own generated hash)
     * @return a randomly generated key pair
     */
    KeyPair generateKeyPair();

    /***
     * transforms the public key stored as bytes back into a key
     * @param bytes read from the masterkey (public key) file
     * @return the restored public key
     */
    PublicKey generateFromBytes(byte[] bytes);

}
