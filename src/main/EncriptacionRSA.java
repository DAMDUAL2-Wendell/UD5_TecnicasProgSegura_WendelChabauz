package main;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;

public class EncriptacionRSA {

	 // Método estático para cifrar una clave AES con RSA
    public static byte[] encryptAESWithRSA(PublicKey publicKey, SecretKey aesKey) { 
        try {
            // Obtener una instancia del cifrador RSA
            Cipher cipher = Cipher.getInstance("RSA"); 
            // Inicializar el cifrador en modo de cifrado con la clave pública
            cipher.init(Cipher.ENCRYPT_MODE, publicKey); 
            // Cifrar la clave AES y devolver el resultado
            return cipher.doFinal(aesKey.getEncoded()); 
        } catch (Exception e) { 
            e.printStackTrace(); 
            return null; 
        }
    }

    // Método estático para descifrar una clave AES con RSA
    public static byte[] decryptAESWithRSA(byte[] encryptedAESKey, PrivateKey privateKey) { 
        try {
            // Obtener una instancia del cifrador RSA
            Cipher cipher = Cipher.getInstance("RSA"); 
            // Inicializar el cifrador en modo de descifrado con la clave privada
            cipher.init(Cipher.DECRYPT_MODE, privateKey); 
            // Descifrar la clave AES cifrada y devolver el resultado
            return cipher.doFinal(encryptedAESKey); 
        } catch (Exception e) { 
            e.printStackTrace(); 
            return null; 
        }
    }
}
