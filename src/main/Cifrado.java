package main;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;


public abstract class Cifrado {

	public static KeyPair GenerarClavesRSA(int longitudBits) {
		// Generar claves RSA
		KeyPairGenerator keygenRSA;
		KeyPair keypairRSA = null;
		try {
			keygenRSA = KeyPairGenerator.getInstance("RSA");
			keygenRSA.initialize(longitudBits);
			keypairRSA = keygenRSA.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error al generar claves RSA." + e.getMessage());
		}

		return keypairRSA;
	}
	
	public static SecretKey generarClaveAES(int BITS_CLAVE_AES) {
	    try {
	        // Generar clave AES
	        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
	        keyGenerator.init(BITS_CLAVE_AES);
	        return keyGenerator.generateKey();
	    } catch (Exception e) {
	        e.printStackTrace();
	        return null;
	    }
	}
	
	public static byte[] readInputStream(InputStream inputStream) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int bytesRead = inputStream.read();
        byte[] data = new byte[bytesRead];
        while ((bytesRead = inputStream.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, bytesRead);
        }
        buffer.flush();
        return buffer.toByteArray();
    }
	
	// Convertir String en PublicKey
	public static PublicKey stringToPublicKey(String publicKeyString){
        try {
        	// Decodificar la cadena Base64 en un array de byte
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
            
            // Crear una especificación de clave X509 a partir de los bytes decodificados
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            
            // Obtener una instancia de KeyFactory para las claves RSA
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            
            // Generar la clave pública a partir de la especificación de clave
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            
            return publicKey;
        }catch(Exception e) {
        	return null;
        }
    }
	
	public static byte[] decryptAES(byte[] claveAES, PrivateKey clavePrivadaRSA) {
	    try {
	        // Inicializar el objeto Cipher para desencriptar con RSA
	        Cipher cifradorRSA = Cipher.getInstance("RSA");
	        cifradorRSA.init(Cipher.DECRYPT_MODE, clavePrivadaRSA);

	        // Desencriptar la clave AES usando RSA
	        return cifradorRSA.doFinal(claveAES);
	    } catch (Exception e) {
	        e.printStackTrace();
	        return null;
	    }
	}


	public static void ImprimirClavesRSA(KeyPair keypairRSA) {
		// Obtener claves pública y privada RSA
		PublicKey publicKey = keypairRSA.getPublic();
		PrivateKey privateKey = keypairRSA.getPrivate();

		// Imprimir claves pública y privada en formato Base64
		System.out.println("Clave pública RSA: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
		System.out.println("Clave privada RSA: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));
	}


	// Imprimir la clave AES descifrada para verificar que coincide con la original
	public static void ImprimirClave(String msg, byte[] key) {
		System.out.println(msg + Base64.getEncoder().encodeToString(key));
	}



	
}
