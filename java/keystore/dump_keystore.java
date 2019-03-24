/**
 * Dump the content of a keystore that contains passwords
 *
 * The entries of a JCEKS (Java Cryptography Extension KeyStore) can be listed
 * using a command such as:
 *
 * keytool -keypasswd -v -keystore store.jks -storetype jceks -storepass changeit -list
 */
import java.io.FileInputStream;
import java.lang.System;
import java.math.BigInteger;
import java.security.KeyStore;
import java.util.Enumeration;
import javax.crypto.SecretKey;

/*
keytool -keypasswd -v -keystore passwords.jks -storetype jceks -storepass changeit -list
*/
public class dump_keystore
{
    public static void main(String[] args) throws Exception
    {
        int arg_pos = 0;

        // Default password is "changeit"
        char[] password = "changeit".toCharArray();

        if (arg_pos + 1 < args.length && args[arg_pos].equals("-p")) {
            password = args[arg_pos + 1].toCharArray();
            arg_pos += 2;
        }

        if (arg_pos >= args.length) {
            System.err.println("Usage: dump_keystore [-p PASSWORD] KEYSTORE [...]");
            java.lang.System.exit(1);
        }

        for (; arg_pos < args.length; arg_pos++) {
            String filename = args[arg_pos];

            FileInputStream fis = new FileInputStream(filename);
            KeyStore ks = KeyStore.getInstance("JCEKS");

            // Password verification may fail with:
            // java.security.UnrecoverableKeyException: Password verification failed
            ks.load(fis, password);

            System.out.println(
                filename + " (password " + new String(password) + "): " +
                ks.size() + " " + (ks.size() >= 2 ? "entries" : "entry"));
            Enumeration<String> ks_enum = ks.aliases();
            while(ks_enum.hasMoreElements()) {
                String alias = ks_enum.nextElement();
                if (ks.isCertificateEntry(alias)) {
                    System.out.println("* " + alias + " (certificate)");
                } else if (ks.isKeyEntry(alias)) {
                    SecretKey secretKey = (SecretKey) ks.getKey(alias, password);
                    System.out.println(
                        "* " + alias + " (key) hex-value: " +
                        new BigInteger(1, secretKey.getEncoded()).toString(16));
                } else {
                    System.out.println("* " + alias + " (unknown)");
                }
            }
        }
    }
}
