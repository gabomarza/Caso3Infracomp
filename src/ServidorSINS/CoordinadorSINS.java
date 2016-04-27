package ServidorSINS;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.KeyPair;
import java.security.Security;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import ServidorSeguro.Coordinador;
import ServidorSeguro.Delegado;
import utils.Seguridad;

public class CoordinadorSINS {

	private static ServerSocket ss;	
	private static final String MAESTRO = "MAESTRO: ";
	static java.security.cert.X509Certificate certSer; /* acceso default */
	static KeyPair keyPairServidor; /* acceso default */
	/**
	 * Puerto en el cual escucha el servidor.
	 */
	public static final int PUERTO = 1234;
	/**
	 * Numero de threads a correr en el servidor
	 */
	public static final int N_THREADS=1;
	
	/**
	 * Tiempo que va a esperar un thread para cliente antes de ser cerrado por inactividad
	 */
	public static final int TIME_OUT=500;
	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception{
		// TODO Auto-generated method stub
		// Adiciona la libreria como un proveedor de seguridad.
		// Necesario para crear llaves.
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());		

		keyPairServidor = Seguridad.grsa();
		certSer = Seguridad.gc(keyPairServidor);

		new Coordinador().iniciarCom();
	}
	/**
	 * Metodo que atiende a los usuarios.
	 */
	public void iniciarCom() {
		final ExecutorService pool = Executors.newFixedThreadPool(N_THREADS);
		Runnable serverRun = new Runnable(){

			@Override
			public void run() {			
				int idActual=0;
				ServerSocket servSock = null;
				int conexionesPerdidas=0;
				try{
					servSock = new ServerSocket(PUERTO);
					System.out.println("Listo para aceptar conexiones.");
					while(true){
						Socket cliente = servSock.accept();
						cliente.setSoTimeout(TIME_OUT);
						DelegadoSINS del = new DelegadoSINS(cliente,idActual);
						pool.execute(del);
						idActual++;
						System.out.println("El numero de clientes no atendidos es:"+conexionesPerdidas);
					}
					
				}
				catch(SocketTimeoutException e)
				{
					System.err.println("Ocurrio un error y no se pudo atender el cliente con id:"+idActual);
					conexionesPerdidas++;
					System.out.println("El numero de clientes no atendidos subio a:"+conexionesPerdidas);
					e.printStackTrace();
				}
				catch (IOException e) {
					System.err.println("Ocurrio un error al escribir el csv " + e.getMessage());
				}
				catch(Exception e){
					System.err.println("Ocurrio un error:");
					e.printStackTrace();
				}finally{
					try{
					}
					catch(Exception e){
						e.printStackTrace();
					}
				}
			}
		};
		Thread serverT = new Thread(serverRun);
		serverT.start();
	}

}