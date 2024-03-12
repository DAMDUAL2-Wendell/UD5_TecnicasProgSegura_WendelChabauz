package main;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.util.Base64;
import javax.crypto.Cipher;


public class Server extends Thread {

	private Socket clientSocket;

	public Server(Socket socket) {
		clientSocket = socket;
	}

	public void run() {
		try {
			System.out.println("Arrancando hilo");

			InputStream is = clientSocket.getInputStream();
			BufferedReader in = new BufferedReader(new InputStreamReader(is));
			PrintWriter out = new PrintWriter(clientSocket.getOutputStream());

			System.out.println("Esperando mensaje de cliente");
			String mensajeCliente = in.readLine();
			System.out.println("Se ha recibido el siguiente mensaje del cliente: " + new String(mensajeCliente));

			// Comprobacion si se ha recibido el mensaje de generar claves
			if (mensajeCliente.equalsIgnoreCase("Generar clave RSA.")) {
				// Cantidad de bits para generar las claves
				int bitsClaveRSA = 2048;

				// Inicialización de los objetos Cipher para cifrado RSA y AES
				Cipher rsaCipher = Cipher.getInstance("RSA");
				Cipher aesCipher = Cipher.getInstance("AES");

				// Generar par de claves RSA
				KeyPair keypairRSA = Cifrado.GenerarClavesRSA(bitsClaveRSA);
				
				// Imprimir claves
				Cifrado.ImprimirClavesRSA(keypairRSA);

				
				// Enviar clave publica RSA al cliente...
				System.out.println("Enviando clave publica RSA al cliente...");
				byte[] publicKeyBytes = keypairRSA.getPublic().getEncoded();
				String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKeyBytes);
				out.println(publicKeyBase64);
				out.flush();
				System.out.println("Clave publica RSA enviada a cliente.");
				
				
				// Leer respuesta del cliente luego de enviar la clave
				System.out.println("Leyendo respuesta de cliente...");
				String respuestaPublicaRSACliente = in.readLine();
				if(respuestaPublicaRSACliente.equals("Clave RSA recibida")) {
					System.out.println("El cliente ha recibido la clave publica RSA correctamente.");
				}else {
					System.out.println("No se ha recibido confirmacion del cliente de haber recibido la clave publica RSA.");
				}
				
				
				// Recibir clave AES del cliente
				System.out.println("Recibiendo clave cifrada AES desde cliente...");
				// Recibir la longitud de la clave AES cifrada del cliente
				int longitudClaveAESCifrada = Integer.parseInt(in.readLine());
				// Array para almacenar la clave AES cifrada
				byte[] claveAESCifrada = new byte[longitudClaveAESCifrada];
				is.read(claveAESCifrada);
				// Imprimir la clave AES cifrada recibida
				Cifrado.ImprimirClave("Clave AES encriptada con RSA: ", claveAESCifrada);

				if(claveAESCifrada != null) {
					System.out.println("Clave AES cifrada recibida correctamente.");
					Cifrado.ImprimirClave("Clave AES encriptada con RSA: ", claveAESCifrada);
				}
				
				// Descifrar clave AES del cliente con clave privada RSA.
				System.out.println("Descifrando clave AES con clave privada RSA.");
				byte[] claveAESDescifrada = EncriptacionAES.descifrarAESconRSA(keypairRSA.getPrivate(), claveAESCifrada);
				if(claveAESDescifrada != null) {
					System.out.println("Clave AES descifrada correctamente con clave privada RSA.");
				}else {
					System.out.println("Error al descifrar la clave AES.");
				}
				
				// Mostrar por pantalla la clave AES descifrada
				Cifrado.ImprimirClave("La clave AES es: ", claveAESDescifrada);
				
				// Enviar confirmacion al cliente de que se ha recibido la clave correctamente
				System.out.println("Enviar confirmacion al cliente de que se ha recibido la clave correctamente");
				out.println("Clave recibida correctamente");
				out.flush();
				
				// Esperar mensajes del cliente.
                System.out.println("Esperando mensaje de cliente.");

                // Leer mensaje cifrado con AES desde el cliente
                String mensajeCifradoAES = in.readLine();
                System.out.println("Mensaje cifrado con AES recibido desde el cliente: " + mensajeCifradoAES);

                // Descifrar mensaje con AES
                String mensajeDescifradoAES = EncriptacionAES.descifrarMensajeAES(claveAESDescifrada, mensajeCifradoAES);
                System.out.println("Mensaje descifrado con AES: " + mensajeDescifradoAES);
                
                // Enviar mensaje cifrado al servidor de respuesta
                String mensaje = "He recibido tu mensaje correctamente.";
                byte[] mensajeCifrado = EncriptacionAES.CifrarMensajeConAES(aesCipher, claveAESDescifrada, mensaje);
                
                // Codificar el mensaje cifrado en Base64
                String mensajeCifradoBase64 = Base64.getEncoder().encodeToString(mensajeCifrado);

                // Enviar el mensaje cifrado codificado en Base64 al cliente
                System.out.println("Enviando mensaje de respueta al cliente.");
                out.println(mensajeCifradoBase64);
                out.flush();

                System.out.println("Mensaje envidado.");

			} else {
				System.out.println("Operacion no reconocida");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		System.out.println("Hilo terminado");
	}
	
	  
	
	
	public static void main(String[] args) {

	    System.out.println("Creando socket servidor");

	    ServerSocket serverSocket = null;

	    try {
	        // Crear un ServerSocket y enlazarlo al puerto 5555
	        InetSocketAddress addr = new InetSocketAddress("localhost", 5555);
	        serverSocket = new ServerSocket();
	        serverSocket.bind(addr);

	        System.out.println("Aceptando conexiones");

	        while (serverSocket != null) {
	            Socket newSocket = serverSocket.accept();
	            System.out.println("Conexión recibida");

	            Server hilo = new Server(newSocket);
	            hilo.start();
	        }
	    } catch (IOException e) {
	        e.printStackTrace();
	    } finally {
	        // Asegurarse de cerrar el ServerSocket cuando haya terminado su uso
	        if (serverSocket != null) {
	            try {
	                serverSocket.close();
	            } catch (IOException e) {
	                e.printStackTrace();
	            }
	        }
	    }

	    System.out.println("Terminado");
	}

}
