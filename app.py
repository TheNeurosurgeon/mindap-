import logging
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError
from dotenv import load_dotenv
import os

# Configuración del logging
logging.basicConfig(
    level=logging.INFO,  # En producción, podrías cambiarlo a WARNING o ERROR
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Cargar variables de entorno desde el archivo .env (si existe)
load_dotenv()

app = Flask(__name__)
# Configuración de la base de datos:
# Si está definida la variable DATABASE_URL en el ambiente, se usará; de lo contrario se usará SQLite.
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Modelo de datos para Proyecto
class Proyecto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f"<Proyecto {self.titulo}>"

# Endpoint para agregar un proyecto
@app.route("/agregar_proyecto", methods=['POST'])
def agregar_proyecto():
    try:
        data = request.get_json()
        if not data or "titulo" not in data or "descripcion" not in data:
            logger.warning("Petición inválida: faltan datos de 'titulo' o 'descripcion'")
            return jsonify({"error": "Faltan datos: titulo y descripcion son requeridos"}), 400

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

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error("Error en la base de datos", exc_info=True)
        return jsonify({"error": str(e)}), 500

    except Exception as e:
        logger.error("Error inesperado", exc_info=True)
        return jsonify({"error": str(e)}), 500

# Endpoint para obtener proyectos con paginación
@app.route("/obtener_proyectos", methods=['GET'])
def obtener_proyectos():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        pagination = Proyecto.query.paginate(page=page, per_page=per_page, error_out=False)
        proyectos = []
        for proyecto in pagination.items:
            proyecto_data = {
                'id': proyecto.id,
                'titulo': proyecto.titulo,
                'descripcion': proyecto.descripcion
            }
            proyectos.append(proyecto_data)
        response = {
            "total": pagination.total,
            "page": page,
            "pages": pagination.pages,
            "per_page": per_page,
            "data": proyectos
        }
        return jsonify(response)

    except Exception as e:
        logger.error("Error al obtener proyectos", exc_info=True)
        return jsonify({"error": str(e)}), 500

# Endpoint para obtener un proyecto específico por ID
@app.route("/obtener_proyecto/<int:id>", methods=['GET'])
def obtener_proyecto(id):
    try:
        proyecto = Proyecto.query.get_or_404(id)
        proyecto_data = {
            'id': proyecto.id,
            'titulo': proyecto.titulo,
            'descripcion': proyecto.descripcion
        }
        return jsonify(proyecto_data)

    except Exception as e:
        logger.error("Error al obtener el proyecto", exc_info=True)
        return jsonify({"error": str(e)}), 500

# Endpoint para actualizar un proyecto
@app.route("/actualizar_proyecto/<int:id>", methods=['PUT'])
def actualizar_proyecto(id):
    try:
        data = request.get_json()
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

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error("Error en la base de datos durante la actualización", exc_info=True)
        return jsonify({"error": str(e)}), 500

    except Exception as e:
        logger.error("Error inesperado durante la actualización", exc_info=True)
        return jsonify({"error": str(e)}), 500

# Endpoint para eliminar un proyecto
@app.route("/eliminar_proyecto/<int:id>", methods=['DELETE'])
def eliminar_proyecto(id):
    try:
        proyecto = Proyecto.query.get_or_404(id)
        db.session.delete(proyecto)
        db.session.commit()
        logger.info(f"Proyecto eliminado correctamente: {proyecto}")
        return jsonify({"mensaje": "Proyecto eliminado correctamente"})

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error("Error en la base de datos durante la eliminación", exc_info=True)
        return jsonify({"error": str(e)}), 500

    except Exception as e:
        logger.error("Error inesperado durante la eliminación", exc_info=True)
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)