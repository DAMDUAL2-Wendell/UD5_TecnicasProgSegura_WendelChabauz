package main;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class EncriptacionAES {
	
	// Método para descifrar un mensaje cifrado con AES
	public static String descifrarMensajeAES(byte[] claveAES, String mensajeCifradoAES) {
	    try {
	        // Inicializar el cifrador AES en modo descifrado con la clave AES proporcionada
	        Cipher cifradorAES = Cipher.getInstance("AES");
	        cifradorAES.init(Cipher.DECRYPT_MODE, new SecretKeySpec(claveAES, "AES"));
	        // Decodificar el mensaje cifrado en Base64 y luego descifrarlo
	        byte[] mensajeDescifrado = cifradorAES.doFinal(Base64.getDecoder().decode(mensajeCifradoAES));
	        // Convertir el mensaje descifrado a String y devolverlo
	        return new String(mensajeDescifrado);
	    } catch (Exception e) {
	        e.printStackTrace();
	        return null;
	    }
	}

	// Método para cifrar un mensaje con AES
	public static String cifrarMensajeAES(SecretKey claveAES, String mensaje) {
	    try {
	        // Inicializar el cifrador AES en modo cifrado con la clave AES proporcionada
	        Cipher cifradorAES = Cipher.getInstance("AES");
	        cifradorAES.init(Cipher.ENCRYPT_MODE, claveAES);
	        // Cifrar el mensaje y codificarlo en Base64
	        byte[] mensajeCifrado = cifradorAES.doFinal(mensaje.getBytes());
	        return Base64.getEncoder().encodeToString(mensajeCifrado);
	    } catch (Exception e) {
	        e.printStackTrace();
	        return null;
	    }
	}

	// Método para descifrar un mensaje cifrado con AES y clave SecretKey
	public static String descifrarMensajeAES2(SecretKey claveAES, byte[] mensajeCifradoBytes) {
	    try {
	        // Inicializar el cifrador AES en modo descifrado con la clave AES proporcionada
	        Cipher cifradorAES = Cipher.getInstance("AES");
	        cifradorAES.init(Cipher.DECRYPT_MODE, claveAES);
	        // Descifrar el mensaje cifrado
	        byte[] mensajeDescifradoBytes = cifradorAES.doFinal(mensajeCifradoBytes);
	        // Convertir el mensaje descifrado a String y devolverlo
	        return new String(mensajeDescifradoBytes);
	    } catch (Exception e) {
	        e.printStackTrace();
	        return null; // Devolver null en caso de error
	    }
	}

	// Método para cifrar un mensaje con AES usando un Cipher preinicializado
	public static byte[] CifrarMensajeConAES(Cipher aesCipher, byte[] decryptedSecretKey, String mensaje) {
	    byte[] encryptedMessage = null;
	    try {
	        // Inicializar el cifrador AES con la clave secreta descifrada
	        aesCipher.init(Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(decryptedSecretKey, "AES"));
	        // Cifrar el mensaje y devolverlo
	        encryptedMessage = aesCipher.doFinal(mensaje.getBytes());
	    } catch (Exception e) {
	        System.out.println("Error al cifrar mensaje con clave AES." + e.getMessage());
	    }
	    return encryptedMessage;
	}

	// Método para descifrar la clave AES cifrada con RSA
	public static byte[] descifrarAESconRSA(PrivateKey clavePrivadaRSA, byte[] claveAESCifrada) {
	    try {
	        // Inicializar el cifrador RSA en modo descifrado con la clave privada RSA
	        Cipher cifradorRSA = Cipher.getInstance("RSA");
	        cifradorRSA.init(Cipher.DECRYPT_MODE, clavePrivadaRSA);
	        // Descifrar la clave AES y devolverla
	        return cifradorRSA.doFinal(claveAESCifrada);
	    } catch (Exception e) {
	        e.printStackTrace();
	        return null;
	    }
	}

	// Método para cifrar la clave AES con RSA
	public static byte[] cifrarAESconRSA(PublicKey clavePublicaRSA, SecretKey claveAES) {
	    try {
	        // Inicializar el cifrador RSA en modo cifrado con la clave pública RSA
	        Cipher cifradorRSA = Cipher.getInstance("RSA");
	        cifradorRSA.init(Cipher.ENCRYPT_MODE, clavePublicaRSA);
	        // Cifrar la clave AES y devolverla
	        return cifradorRSA.doFinal(claveAES.getEncoded());
	    } catch (Exception e) {
	        e.printStackTrace();
	        return null;
	    }
	}

	
	
}
