import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class AESEncryption
{
    private static String algorithm = "AES";
    private static String key = "TalendsSecretKey";
    private static byte[] keyValue = key.getBytes();
    //private static byte[] keyValue=new byte[] {'T','a','l','e','n','d','s','S','e','c','r','e','t','K','e','y'};// your key

    // Performs Encryption
    public static String encrypt(String plainText) throws Exception
    {
        Key key = generateKey();
        Cipher chiper = Cipher.getInstance(algorithm);
        chiper.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = chiper.doFinal(plainText.getBytes());
        String encryptedValue = new BASE64Encoder().encode(encVal);
        return encryptedValue;
    }

    // Performs decryption
    public static String decrypt(String encryptedText) throws Exception
    {
        // generate key
        Key key = generateKey();
        Cipher chiper = Cipher.getInstance(algorithm);
        chiper.init(Cipher.DECRYPT_MODE, key);
        byte[] decordedValue = new BASE64Decoder().decodeBuffer(encryptedText);
        byte[] decValue = chiper.doFinal(decordedValue);
        String decryptedValue = new String(decValue);
        return decryptedValue;
    }

    //generateKey() is used to generate a secret key for AES algorithm
    private static Key generateKey() throws Exception
    {
        Key key = new SecretKeySpec(keyValue, algorithm);
        return key;
    }

    // performs encryption & decryption 
    public static void main(String[] args) throws Exception
    {
        List<String> numbers = new ArrayList<String>();
        numbers.add("923345358725");
        numbers.add("923345358725");
        numbers.add("923345358725");
        numbers.add("03345358711");
        numbers.add("03345358711");

        for (String num: numbers) {
            System.out.println("Encrypted Text : " + encrypt(num));
        }

        System.out.println("Decrypted Text : " + decrypt("wXK+PKMs4/h8wvlyZOdRiA=="));
        System.out.println("Decrypted Text : " + decrypt("tJTiNNalSMR6uOOlTaixPg=="));

        //String data = "TalendsSecretKey";
        //byte[] b = data.getBytes();
        //byte[] key=new byte[] {'T','a','l','e','n','d','s','S','e','c','r','e','t','K','e','y'};// your key
        //System.out.println(Arrays.toString(b));
        //System.out.println(Arrays.toString(key));
    }
}