package logic;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

//slightly modified code from https://stackoverflow.com/a/52163975
public class PasswordPanel extends JPanel {

    private final JPasswordField jFieldPass;
    private final JLabel jLblPass;
    private boolean gainedFocusBefore;

    /**
     * "Hook" method that causes the JPasswordField to request focus when method is
     * first  called.
     */
    public void gainedFocus() {
        if (!gainedFocusBefore) {
            gainedFocusBefore = true;
            jFieldPass.requestFocusInWindow();
        }
    }

    public PasswordPanel(int length, String message) {
        super(new FlowLayout());
        gainedFocusBefore = false;
        jFieldPass = new JPasswordField(length);
        Dimension d = new Dimension();
        d.setSize(30, 22);
        jFieldPass.setMinimumSize(d);
        jFieldPass.setColumns(10);
        jLblPass = new JLabel(message);
        add(jLblPass);
        add(jFieldPass);
    }

    public PasswordPanel() {
        super(new FlowLayout());
        gainedFocusBefore = false;
        jFieldPass = new JPasswordField();
        Dimension d = new Dimension();
        d.setSize(30, 22);
        jFieldPass.setMinimumSize(d);
        jFieldPass.setColumns(10);
        jLblPass = new JLabel("Password: ");
        add(jLblPass);
        add(jFieldPass);
    }

    public String getPassword() {
        return String.valueOf(jFieldPass.getPassword());
    }

    public String getPasswordString() {
        StringBuilder passBuilder = new StringBuilder();

        String pwd = this.getPassword();
        if (pwd.length() > 0) {
            for (char c : pwd.toCharArray()) {
                passBuilder.append(c);
            }
        }

        return passBuilder.toString();
    }

    private static String displayDialog(Component parent, final PasswordPanel panel, String title) {
        String password = null;
    /* For some reason, using `JOptionPane(panel, JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE)`
    does not give the same results as setting values after creation, which is weird */
        JOptionPane op = new JOptionPane(panel);
        op.setMessageType(JOptionPane.QUESTION_MESSAGE);
        op.setOptionType(JOptionPane.OK_CANCEL_OPTION);
        JDialog dlg = op.createDialog(parent, title);
        // Ensure the JPasswordField is able to request focus when the dialog is first shown.
        dlg.addWindowFocusListener(new WindowAdapter() {
            @Override
            public void windowGainedFocus(WindowEvent e) {
                panel.gainedFocus();
            }
        });
        dlg.setDefaultCloseOperation(JOptionPane.OK_OPTION); // necessary?

        dlg.setVisible(true);

        Object val = op.getValue();
        if (null != val && val.equals(JOptionPane.OK_OPTION)) {
            password = panel.getPasswordString();
        }

        return password;
    }

    public static String showDialog(Component parent, String title, String message) {
        final PasswordPanel pPnl = new PasswordPanel(100, message);
        return displayDialog(parent, pPnl, title);
    }

    public static String showDialog(Component parent, String title, int passwordLength, String message) {
        final PasswordPanel pPnl = new PasswordPanel(passwordLength, message);
        return displayDialog(parent, pPnl, title);
    }
}
