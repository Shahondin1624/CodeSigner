package logic;

import asymetricEncryption.AsymmetricAlgorithmProvider;
import hashing.HashParameters;
import hashing.HashProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class MainWrapper {

    private static final Logger logger = LoggerFactory.getLogger(MainWrapper.class);

    /***
     *
     * @param paths of the files that should be monitored for modification. Have to be supplied relative to working dir
     * @param hashedPassword the password has to be hashed manually and then provided as a string
     * @param parameters have to be those that have been used when generating the password hash
     */
    public static void execute(String[] paths, String hashedPassword, HashProvider hashProvider,
                               AsymmetricAlgorithmProvider asymmetricAlgorithmProvider, HashParameters parameters) {
        try {
            logger.debug("Initializing checkup procedure");
            Utilities util = new Utilities(hashProvider, asymmetricAlgorithmProvider);
            boolean masterKeyExists = util.masterKeyFileExists();
            boolean hashFileExists = util.hashFileExists();
            if (masterKeyExists && hashFileExists) {
                if (!util.hashesMatch(paths)) {
                    logger.debug("Checksums do not match, a new hash has to be generated");
                    executeCompleteSignProcess(paths, hashedPassword, util, parameters);
                }
            } else {
                logger.debug("MasterKey file exists: {}; HashFile exists {}. Because of that a new signing is required",
                        masterKeyExists, hashFileExists);
                executeCompleteSignProcess(paths, hashedPassword, util, parameters);
            }
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeySpecException |
                BadPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    private static void executeCompleteSignProcess(String[] paths, String hashedPassword, Utilities util, HashParameters parameters)
            throws NoSuchAlgorithmException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeyException {
        String password = inquirePasswordFromUser("Insert password to regenerate checksum");
        //Program execution has to stop when an invalid program is supplied
        if (!util.passwordMatches(password, hashedPassword, parameters)) {
            logger.error("Wrong password supplied. Aborting execution");
            System.exit(-1);
        }
        logger.debug("Attempting a new sign");
        util.sign(paths);
        //commented out because when a trusted password is supplied the code should run immediately and not need to be restarted
//        logger.debug("Signing completed. System terminates now");
//        System.exit(1);
    }

    private static String inquirePasswordFromUser(String message) {
        String input =  PasswordPanel.showDialog(null, "Enter password", message);
        if (input != null) {
            return input;
        } else {
            logger.error("User did not supply a password, aborting execution");
            System.exit(-1);
            return null;
        }
    }

}
