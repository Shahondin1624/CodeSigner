package logic;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.*;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class MainWrapper {

    private static final Logger logger = LoggerFactory.getLogger(MainWrapper.class);

    /***
     *
     * @param paths relative to working dir
     * @param hashedPassword use {@link PasswordHasher#main(String[])} and supply your password as only argument to generate
     *                       a valid hash
     */
    public static void execute(String[] paths, String hashedPassword) {
        try {
            logger.debug("Initializing checkup procedure");
            Utilities util = new Utilities();
            boolean masterKeyExists = util.masterKeyFileExists();
            boolean hashFileExists = util.hashFileExists();
            if (masterKeyExists && hashFileExists) {
                if (!util.hashesMatch(paths)) {
                    logger.debug("Checksums do not match, a new hash has to be generated");
                    executeCompleteSignProcess(paths, hashedPassword, util);
                }
            } else {
                logger.debug("MasterKey file exists: {}; HashFile exists {}. Because of that a new signing is required",
                        masterKeyExists, hashFileExists);
                executeCompleteSignProcess(paths, hashedPassword, util);
            }
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeySpecException |
                BadPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }
    //TODO make input field a password field
    private static void executeCompleteSignProcess(String[] paths, String hashedPassword, Utilities util) throws NoSuchAlgorithmException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeyException {
        String password = JOptionPane.showInputDialog("Insert password to regenerate checksum");
        password = Utilities.bytesToHex(util.hashPassword(password));
        //Program execution has to stop when an invalid program is supplied
        if (!password.equals(hashedPassword)) {
            logger.error("Wrong password supplied. Aborting execution");
            System.exit(-1);
        }
        logger.debug("Attempting a new sign");
        util.sign(paths);
        logger.debug("Signing completed. System terminates now");
        System.exit(1);
    }


}
