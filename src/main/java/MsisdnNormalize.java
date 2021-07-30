import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class MsisdnNormalize {

    public static String getMd5(String input)
    {
        try {

            // Static getInstance method is called with hashing MD5
            MessageDigest md = MessageDigest.getInstance("MD5");

            // digest() method is called to calculate message digest
            //  of an input digest() return array of byte
            byte[] messageDigest = md.digest(input.getBytes());

            // Convert byte array into signum representation
            BigInteger no = new BigInteger(1, messageDigest);

            // Convert message digest into hex value
            String hashtext = no.toString(16);
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }
            return hashtext;
        }

        // For specifying wrong message digest algorithms
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    public static String getMask(String input) throws NullPointerException
    {
        if(input != null && !input.isEmpty()){
            if(input.startsWith("92"))
            {
                return getMd5(input);
            }
            else {
                String normalized = input.replaceFirst("0","92");
                return getMd5(normalized);
            }
        }
        else {
            throw new NullPointerException("Input for MSISDN cannot be null");
        }
    }

    // Driver code
    public static void main(String args[])
    {
        /*List<String> numbers = new ArrayList<String>();
        numbers.add("923345358725");
        numbers.add("03345358725");
        numbers.add("923345358725");
        numbers.add("03345358711");
        numbers.add("03345358711");

        for (String num: numbers) {
            System.out.println("Your input is: " + getMask(num));
        }*/

        String number = "923345358725";
        String num="92"+number.substring(number.length()-10);
        System.out.println(num);


    }
}
