import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.charset.StandardCharsets.US_ASCII;


public class AES {

    private static final byte[] SALTED = "Salted__".getBytes(US_ASCII);
    private static final String passphrase = "yourSecretKey";
    private static final byte[] salt = "yourSalt".getBytes();
    private static byte[] _encrypt(byte[] input, byte[] passphrase) throws Exception
    {
        Object[] keyIv = deriveKeyAndIv(passphrase, salt);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec((byte[])keyIv[0], "AES"), new IvParameterSpec((byte[])keyIv[1]));
        byte[] enc = cipher.doFinal(input);
        return concat(concat(SALTED, salt), enc);
    }
    private static byte[] _decrypt(byte[] data, byte[] passphrase) throws Exception
    {
        if (!Arrays.equals(Arrays.copyOfRange(data, 0, 8), SALTED)) {
            throw new IllegalArgumentException("Invalid crypted data");
        }
        Object[] keyIv = deriveKeyAndIv(passphrase, salt);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec((byte[])keyIv[0], "AES"), new IvParameterSpec((byte[])keyIv[1]));
        return cipher.doFinal(data, 16, data.length - 16);
    }
    private static Object[] deriveKeyAndIv(byte[] passphrase, byte[] salt) throws Exception
    {
        final MessageDigest md5 = MessageDigest.getInstance("MD5");
        final byte[] passSalt = concat(passphrase, salt);
        byte[] dx = new byte[0];
        byte[] di = new byte[0];
        for (int i = 0; i < 3; i++) {
            di = md5.digest(concat(di, passSalt));
            dx = concat(dx, di);
        }
        return new Object[]{Arrays.copyOfRange(dx, 0, 32), Arrays.copyOfRange(dx, 32, 48)};
    }
    private static byte[] concat(byte[] a, byte[] b)
    {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
    public static String encrypt(String input) throws Exception {
        return Base64.getEncoder().encodeToString(_encrypt(input.getBytes(UTF_8), passphrase.getBytes(UTF_8)));
    }

    public static String decrypt(String input) throws Exception {
        return new String(_decrypt(Base64.getDecoder().decode(input), passphrase.getBytes(UTF_8)), UTF_8);
    }
    public static void main(String[] args) throws Exception {
        List<String> numbers = new ArrayList<String>();
        numbers.add("923345358725");
        numbers.add("923345358725");
        numbers.add("923345358725");
        numbers.add("923345358725");
        numbers.add("923345358725");
        numbers.add("923345358725");
        numbers.add("923345358725");
        numbers.add("923345358711");
        numbers.add("923345358711");
        numbers.add("923345358711");
        numbers.add("923345358711");
        numbers.add("923345358711");
        numbers.add("923345358711");
        numbers.add("923345358711");
        numbers.add("923345358711");
        numbers.add("923345358720");
        numbers.add("923345358721");
        numbers.add("923345358727");

        for (String num: numbers) {
            System.out.println("Encrypted Text : " + encrypt(num));
        }

        System.out.println(decrypt("U2FsdGVkX195b3VyU2FsdCNuHglmWs3gEwNAKidNfIw="));

    }
}
