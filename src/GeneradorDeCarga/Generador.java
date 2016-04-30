package GeneradorDeCarga;

import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class Generador 
{
	/**
	 * El generador
	 */
	private LoadGenerator generador;
	
	/**
	 * El constructor
	 */
	public Generador()
	{
		Task tarea = crearTarea();
		int numTareas = 80;
		int tiempoEntreTareas = 100;
		generador = new LoadGenerator("Prueba", numTareas, tarea, tiempoEntreTareas);
		generador.generate();
	}
	
	/**
	 * Creador de tareas
	 */
	private Task crearTarea()
	{
		return new TareaConSeguridad();
	}
	
	/**
	 * Main
	 */
	public static void main(String[] args) {
		@SuppressWarnings("unused")
		Generador gen = new Generador();
	}
}
