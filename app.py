import os
import logging
from flask import Flask, request, jsonify, Blueprint
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from dotenv import load_dotenv
from flasgger import Swagger
from werkzeug.exceptions import NotFound, BadRequest, InternalServerError

# Cargar variables de entorno del archivo .env (si existe)
load_dotenv()

# Configuración del logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Inicialización de la aplicación Flask
app = Flask(__name__)

# Configuración de la base de datos:
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicialización de la extensión SQLAlchemy
db = SQLAlchemy(app)

# Configuración de Swagger para la documentación de la API
swagger = Swagger(app)

# Modelo de datos para Proyecto
class Proyecto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f"<Proyecto {self.titulo}>"

# Creación de Blueprint para endpoints relacionados con 'proyectos'
proyecto_bp = Blueprint('proyectos', __name__)

@proyecto_bp.route("", methods=["POST"])
def agregar_proyecto():
    """
    Agrega un nuevo proyecto.
    ---
    tags:
      - Proyectos
    parameters:
      - in: body
        name: body
        description: Datos del proyecto a agregar.
        required: true
        schema:
          type: object
          required:
            - titulo
            - descripcion
          properties:
            titulo:
              type: string
            descripcion:
              type: string
    responses:
      201:
        description: Proyecto agregado correctamente.
        schema:
          type: object
          properties:
            mensaje:
              type: string
            id:
              type: integer
            titulo:
              type: string
            descripcion:
              type: string
      400:
        description: Datos inválidos.
      409:
        description: El proyecto ya existe (por ejemplo, por título único).
      500:
        description: Error en el servidor.
    """
    try:
        data = request.get_json()
        if not data or "titulo" not in data or "descripcion" not in data:
            logger.warning("Petición inválida: faltan datos de 'titulo' o 'descripcion'")
            raise BadRequest("Faltan datos: titulo y descripcion son requeridos")

        proyecto = Proyecto(titulo=data['titulo'], descripcion=data['descripcion'])
        db.session.add(proyecto)
        db.session.commit()
        logger.info(f"Proyecto agregado correctamente: {proyecto}")
        return jsonify({
            "mensaje": "Proyecto agregado correctamente",
            "id": proyecto.id,
            "titulo": proyecto.titulo,
            "descripcion": proyecto.descripcion
        }), 201

    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
    except IntegrityError as e:
        db.session.rollback()
        logger.error("Error de integridad en la base de datos al agregar proyecto", exc_info=True)
        return jsonify({"error": "El proyecto ya existe"}), 409
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error("Error en la base de datos al agregar proyecto", exc_info=True)
        return jsonify({"error": "Error en la base de datos"}), 500
    except Exception as e:
        logger.error("Error inesperado al agregar proyecto", exc_info=True)
        return jsonify({"error": "Error interno del servidor"}), 500

@proyecto_bp.route("", methods=["GET"])
def obtener_proyectos():
    """
    Obtiene la lista de proyectos con paginación.
    ---
    tags:
      - Proyectos
    parameters:
      - name: page
        in: query
        type: integer
        description: Número de página (por defecto 1).
      - name: per_page
        in: query
        type: integer
        description: Número de proyectos por página (por defecto 10).
    responses:
      200:
        description: Lista de proyectos paginados.
        schema:
          type: object
          properties:
            total:
              type: integer
            page:
              type: integer
            pages:
              type: integer
            per_page:
              type: integer
            data:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: integer
                  titulo:
                    type: string
                  descripcion:
                    type: string
      500:
        description: Error en el servidor.
    """
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        pagination = Proyecto.query.paginate(page=page, per_page=per_page, error_out=False)
        proyectos = [{
            'id': proyecto.id,
            'titulo': proyecto.titulo,
            'descripcion': proyecto.descripcion
        } for proyecto in pagination.items]

        response = {
            "total": pagination.total,
            "page": page,
            "pages": pagination.pages,
            "per_page": per_page,
            "data": proyectos
        }
        return jsonify(response)

    except SQLAlchemyError as e:
        logger.error("Error al obtener proyectos desde la base de datos", exc_info=True)
        return jsonify({"error": "Error al acceder a la base de datos"}), 500
    except Exception as e:
        logger.error("Error inesperado al obtener proyectos", exc_info=True)
        return jsonify({"error": "Error interno del servidor"}), 500

@proyecto_bp.route("/<int:id>", methods=["GET"])
def obtener_proyecto(id):
    """
    Obtiene un proyecto específico por ID.
    ---
    tags:
      - Proyectos
    parameters:
      - name: id
        in: path
        type: integer
        required: true
        description: ID del proyecto a obtener.
    responses:
      200:
        description: Proyecto obtenido correctamente.
        schema:
          type: object
          properties:
            id:
              type: integer
            titulo:
              type: string
            descripcion:
              type: string
      404:
        description: Proyecto no encontrado.
      500:
        description: Error en el servidor.
    """
    try:
        proyecto = Proyecto.query.get_or_404(id)
        proyecto_data = {
            'id': proyecto.id,
            'titulo': proyecto.titulo,
            'descripcion': proyecto.descripcion
        }
        return jsonify(proyecto_data)

    except NotFound:
        logger.warning(f"Proyecto con ID {id} no encontrado")
        return jsonify({"error": "Proyecto no encontrado"}), 404
    except SQLAlchemyError as e:
        logger.error(f"Error al obtener el proyecto con ID {id} desde la base de datos", exc_info=True)
        return jsonify({"error": "Error al acceder a la base de datos"}), 500
    except Exception as e:
        logger.error(f"Error inesperado al obtener el proyecto con ID {id}", exc_info=True)
        return jsonify({"error": "Error interno del servidor"}), 500

@proyecto_bp.route("/<int:id>", methods=["PUT"])
def actualizar_proyecto(id):
    """
    Actualiza un proyecto existente.
    ---
    tags:
      - Proyectos
    parameters:
      - name: id
        in: path
        type: integer
        required: true
        description: ID del proyecto a actualizar.
      - in: body
        name: body
        description: Datos para actualizar el proyecto.
        required: true
        schema:
          type: object
          properties:
            titulo:
              type: string
            descripcion:
              type: string
    responses:
      200:
        description: Proyecto actualizado correctamente.
        schema:
          type: object
          properties:
            mensaje:
              type: string
            id:
              type: integer
            titulo:
              type: string
            descripcion:
              type: string
      400:
        description: Datos inválidos.
      404:
        description: Proyecto no encontrado.
      500:
        description: Error en el servidor.
    """
    try:
        data = request.get_json()
        if not data:
            logger.warning(f"Petición inválida al actualizar proyecto {id}: no se proporcionaron datos")
            raise BadRequest("No se proporcionaron datos para actualizar")

        proyecto = Proyecto.query.get_or_404(id)

        if "titulo" in data:
            proyecto.titulo = data["titulo"]
        if "descripcion" in data:
            proyecto.descripcion = data["descripcion"]

        db.session.commit()
        logger.info(f"Proyecto actualizado correctamente: {proyecto}")
        return jsonify({
            "mensaje": "Proyecto actualizado correctamente",
            "id": proyecto.id,
            "titulo": proyecto.titulo,
            "descripcion": proyecto.descripcion
        })

    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
    except NotFound:
        logger.warning(f"Proyecto con ID {id} no encontrado para actualizar")
        return jsonify({"error": "Proyecto no encontrado"}), 404
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Error en la base de datos al actualizar proyecto {id}", exc_info=True)
        return jsonify({"error": "Error al acceder a la base de datos"}), 500
    except Exception as e:
        logger.error(f"Error inesperado al actualizar proyecto {id}", exc_info=True)
        return jsonify({"error": "Error interno del servidor"}), 500

@proyecto_bp.route("/<int:id>", methods=["DELETE"])
def eliminar_proyecto(id):
    """
    Elimina un proyecto existente.
    ---
    tags:
      - Proyectos
    parameters:
      - name: id
        in: path
        type: integer
        required: true
        description: ID del proyecto a eliminar.
    responses:
      200:
        description: Proyecto eliminado correctamente.
      404:
        description: Proyecto no encontrado.
      500:
        description: Error en el servidor.
    """
    try:
        proyecto = Proyecto.query.get_or_404(id)
        db.session.delete(proyecto)
        db.session.commit()
        logger.info(f"Proyecto eliminado correctamente: {proyecto}")
        return jsonify({"mensaje": "Proyecto eliminado correctamente"})

    except NotFound:
        logger.warning(f"Proyecto con ID {id} no encontrado para eliminar")
        return jsonify({"error": "Proyecto no encontrado"}), 404
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Error en la base de datos al eliminar proyecto {id}", exc_info=True)
        return jsonify({"error": "Error al acceder a la base de datos"}), 500
    except Exception as e:
        logger.error(f"Error inesperado al eliminar proyecto {id}", exc_info=True)
        return jsonify({"error": "Error interno del servidor"}), 500

# Registro del Blueprint en la aplicación
app.register_blueprint(proyecto_bp, url_prefix="/proyectos")

# Manejo personalizado de errores HTTP
@app.errorhandler(BadRequest)
def bad_request(e):
    logger.warning(f"Solicitud incorrecta: {e}")
    return jsonify({"error": str(e)}), 400

@app.errorhandler(NotFound)
def not_found(e):
    logger.warning(f"Recurso no encontrado: {e}")
    return jsonify({"error": "Recurso no encontrado"}), 404

@app.errorhandler(InternalServerError)
def internal_server_error(e):
    logger.error(f"Error interno del servidor: {e}", exc_info=True)
    return jsonify({"error": "Error interno del servidor"}), 500

@app.errorhandler(SQLAlchemyError)
def database_error(e):
    db.session.rollback()
    logger.error(f"Error de base de datos: {e}", exc_info=True)
    return jsonify({"error": "Error en la base de datos"}), 500

@app.errorhandler(Exception)
def general_error(e):
    logger.error(f"Error general no manejado: {e}", exc_info=True)
    return jsonify({"error": "Ha ocurrido un error inesperado"}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
