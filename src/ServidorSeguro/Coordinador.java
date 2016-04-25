package ServidorSeguro;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.lang.management.ManagementFactory;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.KeyPair;
import java.security.Security;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import jxl.Workbook;
import jxl.write.WritableSheet;
import jxl.write.WritableWorkbook;
import jxl.write.biff.File;
import utils.*;

public class Coordinador {

	private static ServerSocket ss;	
	private static final String MAESTRO = "MAESTRO: ";
	static java.security.cert.X509Certificate certSer; /* acceso default */
	static KeyPair keyPairServidor; /* acceso default */
	/**
	 * Puerto en el cual escucha el servidor.
	 */
	public static final int PUERTO = 8080;

	/**
	 * Numero de threads a correr en el servidor
	 */
	public static final int N_THREADS=1;

	/**
	 * Tiempo que va a esperar un thread para cliente antes de ser cerrado por inactividad
	 */
	public static final int TIME_OUT=10000;
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
				Long timeThread = null;
				ServerSocket servSock = null;
				int conexionesPerdidas=0;
				try{
					servSock = new ServerSocket(PUERTO);
					System.out.println("Listo para aceptar conexiones.");
					while(true){

						Socket cliente = servSock.accept();
						cliente.setSoTimeout(TIME_OUT);
						Delegado del = new Delegado(cliente,idActual);
						pool.execute(del);
						idActual++;
					}
				}catch(SocketTimeoutException e)
				{
					System.err.println("Ocurrio un error y no se pudo atender el cliente con id:"+idActual);
					conexionesPerdidas++;
					//Imprimir
					e.printStackTrace();
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