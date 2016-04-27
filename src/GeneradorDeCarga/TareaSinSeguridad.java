package GeneradorDeCarga;

import Ejecucion.AppAgenteSINS;
import uniandes.gload.core.Task;

public class TareaSinSeguridad extends Task{

	public void execute() {
			
		    AppAgenteSINS c= new AppAgenteSINS(true);
		    System.out.println("Esta es la consola");
		    
				c.inicializar();
				System.out.println("VA ACA1");
				c.inicioStuff();
				System.out.println("VA ACA2");
				c.certificacion();
				System.out.println("VA ACA3");
				c.recibeLlaveSimetrica();
				System.out.println("VA ACA4");
				c.manejoPosicion();
				System.out.println("Proceso terminado exitosamente");
			
	}

	public void fail() {

		System.out.println(Task.MENSAJE_FAIL);
	}

	
	public void success() {

		System.out.println(Task.OK_MESSAGE);
	}



}