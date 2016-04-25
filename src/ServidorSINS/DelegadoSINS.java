package ServidorSINS;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.crypto.SecretKey;
import utils.*;

public class DelegadoSINS extends Thread {
	// Constantes
	public static final String STATUS = "ESTADO";
	public static final String OK = "OK";
	public static final String ALGORITMOS = "ALGORITMOS";
	public static final String HMACMD5 = "HMACMD5";
	public static final String HMACSHA1 = "HMACSHA1";
	public static final String HMACSHA256 = "HMACSHA256";
	public static final String CERTSRV = "CERTSRV";
	public static final String CERCLNT = "CERCLNT";
	public static final String SEPARADOR = ":";
	public static final String HOLA = "HOLA";
	public static final String INICIO = "INICIO";
	public static final String ERROR = "ERROR";
	public static final String ERRORPRT = "ERROR EN PROTOCOLO:";
	public static final String REC = "recibio-";
	// Atributos
	private Socket sc = null;
	private String dlg;
	
	DelegadoSINS (Socket csP, int idP) {
		sc = csP;
		dlg = new String("dlg " + idP + ": ");
	}
	
	public void run() {
		String me = new String(STATUS+SEPARADOR+ERROR);
		String mok = new String(STATUS+SEPARADOR+OK);
		String mt;
		String linea;
	    System.out.println(dlg + "Empezando atencion.");
	        try {

				PrintWriter ac = new PrintWriter(sc.getOutputStream() , true);
				BufferedReader dc = new BufferedReader(new InputStreamReader(sc.getInputStream()));

				/***** Fase 1: Inicio *****/
				linea = dc.readLine();
				if (!linea.equals(HOLA)) {
					ac.println(me);
			        sc.close();
					throw new Exception(dlg + ERRORPRT + REC + linea +"-terminando.");
				}
				System.out.println(dlg + REC + linea + "-continuando.");
				ac.println(INICIO);

				/***** Fase 2: Algoritmos *****/
				linea = dc.readLine();
				if (!(linea.contains(SEPARADOR) && linea.split(SEPARADOR)[0].equals(ALGORITMOS))) {
					ac.println(me);
					sc.close();
					throw new Exception(dlg + ERRORPRT + REC + linea +"-terminando.");
				}
				
				String[] algoritmos = linea.split(SEPARADOR);
				if (!algoritmos[1].equals(Seguridad.DES) && !algoritmos[1].equals(Seguridad.AES) &&
					!algoritmos[1].equals(Seguridad.BLOWFISH) && !algoritmos[1].equals(Seguridad.RC4)){
					ac.println(STATUS+SEPARADOR+ERROR);
					sc.close();
					throw new Exception(dlg + ERRORPRT + "Alg.Simetrico" + REC + algoritmos + "-terminando.");
				}
				if (!algoritmos[2].equals(Seguridad.RSA)) {
					ac.println(me);
					sc.close();
					throw new Exception(dlg + ERRORPRT + "Alg.Asimetrico." + REC + algoritmos + "-terminando.");
				}
				if (!(algoritmos[3].equals(HMACMD5) || algoritmos[3].equals(HMACSHA1) ||
					  algoritmos[3].equals(HMACSHA256))) {
					ac.println(me);
					sc.close();
					throw new Exception(dlg + ERRORPRT + "AlgHash." + REC + algoritmos + "-terminando.");
				}
				System.out.println(dlg + REC + linea + "-continuando.");
				ac.println(mok);

				/***** Fase 3: Recibe certificado del cliente *****/
				linea = dc.readLine();
				mt = new String(CERCLNT + SEPARADOR);
				if (!(linea.equals(mt))) {
					ac.println(me);
					sc.close();
					throw new Exception(dlg + ERRORPRT + "CERCLNT." + REC + linea + "-terminando.");
				}
				System.out.println(dlg + REC + mt + "-continuando.");
				int offset = 0;
				byte[] certificadoServidorBytes = new byte[520];
				int numBytesLeidos = sc.getInputStream().read(certificadoServidorBytes,offset,520-offset);
				if (numBytesLeidos<=0) {
					ac.println(me);
					sc.close();
					throw new Exception(dlg + "Error recibiendo certificado. terminando.");					
				}
				CertificateFactory creador = CertificateFactory.getInstance("X.509");
				InputStream in = new ByteArrayInputStream(certificadoServidorBytes);
				X509Certificate certificadoCliente = (X509Certificate)creador.generateCertificate(in);
				System.out.println(dlg + "recibio certificado del cliente. continuando.");
				
				/***** Fase 4: Envia certificado del servidor *****/
				mt= new String(CERTSRV + SEPARADOR);
				ac.println(mt);
				byte[] mybyte = CoordinadorSINS.certSer.getEncoded( );
				sc.getOutputStream( ).write( mybyte );
				sc.getOutputStream( ).flush( );
				System.out.println(dlg + "envio certificado del servidor. continuando.");
				linea = dc.readLine();
				if (!(linea.equals(mok))) {
					ac.println(me);
					throw new Exception(dlg + ERRORPRT + REC + linea + "-terminando.");
				}
				System.out.println(dlg + "recibio-" + linea + "-continuando.");

				/***** Fase 5: Envia llave simetrica *****/
				
				ac.println("DATA");
				System.out.println(dlg + "envio llave simetrica al cliente. continuado.");
				
				/***** Fase 6: Confirma llave simetrica *****/
				linea = dc.readLine();
				if (!linea.equals("DATA")) {
					ac.println(me);
					throw new Exception(dlg + "Error confirmando llave. terminando.");
				}
				ac.println(mok);
				
				/***** Fase 7: Actualizacion del agente *****/
				linea = dc.readLine();
				if (!linea.equals("ACT1")) {
					ac.println(me);
					throw new Exception(dlg + "Error en ACT1. terminando.");
				}
				linea = dc.readLine();
				if (!linea.equals("ACT2")) {
					ac.println(me);
					throw new Exception(dlg + "Error en ACT2. terminando.");
				}
				System.out.println(dlg + "descifro informacion-" + "-continuado.");
				boolean verificacion = true;
				if (verificacion) {
					System.out.println(dlg + "verificacion de integridad:OK. -continuado.");
					ac.println(mok);
				} else {
					ac.println(me);
					throw new Exception(dlg + "Error en verificacion de integridad. -terminando.");
				}
		        sc.close();
		        System.out.println(dlg + "Termino exitosamente.");
				
	        } catch (Exception e) {
	          e.printStackTrace();
	        }
	}
}