package main;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;

import javax.crypto.Cipher;

public class Server extends Thread {

	private Socket clientSocket;

	public Server(Socket socket) {
		clientSocket = socket;
	}

	public void run() {
		try {
			System.out.println("Arrancando hilo");

			DataInputStream dis = new DataInputStream(clientSocket.getInputStream()); 
			OutputStream os = clientSocket.getOutputStream();

			System.out.println("Esperando mensaje de cliente");

			byte[] buffer = new byte[255];
			
			
			String mensajeCliente = new String(buffer,0,dis.read(buffer)).trim();

			System.out.println("Mensaje cliente: " + new String(mensajeCliente));

			if (mensajeCliente.equalsIgnoreCase("Generar clave RSA.")) {
				// Cantidad de bits para generar las claves
				int bitsClaveRSA = 2048;
				int bitsClaveAES = 256;

				// Inicialización de los objetos Cipher para cifrado RSA y AES
				Cipher rsaCipher = Cipher.getInstance("RSA");
				Cipher aesCipher = Cipher.getInstance("AES");

				// Generar par de claves RSA
				KeyPair keypairRSA = Cifrado.GenerarClavesRSA(bitsClaveRSA);
				
				// Imprimir claves
				Cifrado.ImprimirClavesRSA(keypairRSA);
				
				// Enviar clave publica RSA al cliente
				System.out.println("Enviando clave publica RSA al cliente...");
				os.write(keypairRSA.getPublic().getEncoded());
				
				
				System.out.println("Recibiendo clave cifrada AES desde cliente...");
				// Recibir clave AES cifrada del cliente
				byte[] claveAESCifradaCliente = Cifrado.leerDatosDataInputStream(dis, dis.readInt());

				System.out.println("Descifrando clave AES con clave publica RSA.");
				// Descifrar clave AES con clave privada RSA del servidor
				byte[] claveAESDescifrada = Cifrado.descifrarAESconRSA(keypairRSA.getPrivate(), claveAESCifradaCliente);

				
				Cifrado.ImprimirClave("La clave AES es: ", claveAESDescifrada);
				
				
				System.out.println("Esperando mensaje de cliente.");



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
