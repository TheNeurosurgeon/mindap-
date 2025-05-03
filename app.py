from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError
from dotenv import load_dotenv
import os

# Carga de variables de entorno desde un archivo .env (si lo tienes configurado)
load_dotenv()

app = Flask(__name__)
# Configuración de la base de datos: Usa DATABASE_URL si está definida en las variables de entorno, sino usa SQLite por defecto
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Definición del modelo Proyecto
class Proyecto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f"<Proyecto {self.titulo}>"

# Endpoint para agregar un nuevo proyecto
@app.route("/agregar_proyecto", methods=['POST'])
def agregar_proyecto():
    try:
        data = request.get_json()
        if not data or "titulo" not in data or "descripcion" not in data:
            return jsonify({"error": "Faltan datos: titulo y descripcion son requeridos"}), 400
        proyecto = Proyecto(titulo=data['titulo'], descripcion=data['descripcion'])
        db.session.add(proyecto)
        db.session.commit()
        return jsonify({
            "mensaje": "Proyecto agregado correctamente",
            "id": proyecto.id,
            "titulo": proyecto.titulo,
            "descripcion": proyecto.descripcion
        }), 201
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500
    except Exception as e:
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
        return jsonify({"error": str(e)}), 500

# Endpoint para obtener un proyecto por su ID
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
        return jsonify({"error": str(e)}), 500

# Endpoint para actualizar un proyecto existente
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
        return jsonify({
            "mensaje": "Proyecto actualizado correctamente",
            "id": proyecto.id,
            "titulo": proyecto.titulo,
            "descripcion": proyecto.descripcion
        })
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Endpoint para eliminar un proyecto
@app.route("/eliminar_proyecto/<int:id>", methods=['DELETE'])
def eliminar_proyecto(id):
    try:
        proyecto = Proyecto.query.get_or_404(id)
        db.session.delete(proyecto)
        db.session.commit()
        return jsonify({"mensaje": "Proyecto eliminado correctamente"})
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
