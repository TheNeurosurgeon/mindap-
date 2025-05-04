import os
import logging
from flask import Flask, request, jsonify, Blueprint, current_app, g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from dotenv import load_dotenv
from flasgger import Swagger
from werkzeug.exceptions import NotFound, BadRequest, InternalServerError, Unauthorized
from typing import Dict, Any, List, Optional
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import pytest  # Importamos pytest

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
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')  # ¡Cambiar en producción!

# Inicialización de la extensión SQLAlchemy
db = SQLAlchemy(app)

# Configuración de Swagger para la documentación de la API
swagger = Swagger(app)

# Modelo de datos para Usuario
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    rol = db.Column(db.String(20), default='usuario', nullable=False)  # 'usuario' o 'admin'

    def set_password(self, password: str) -> None:
        """Hashea la contraseña y la guarda."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verifica si la contraseña coincide con el hash almacenado."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<Usuario {self.username}>"

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'username': self.username,
            'rol': self.rol
        }

# Modelo de datos para Proyecto
class Proyecto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(100), nullable=False, unique=True)
    descripcion = db.Column(db.Text, nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False) #Relacion con el usuario
    usuario = db.relationship('Usuario', backref=db.backref('proyectos', lazy=True))

    def __repr__(self):
        return f"<Proyecto {self.titulo}>"

    def to_dict(self) -> Dict[str, Any]:
        """Convierte el objeto Proyecto a un diccionario."""
        return {
            'id': self.id,
            'titulo': self.titulo,
            'descripcion': self.descripcion,
            'usuario_id': self.usuario_id
        }

# Función para generar tokens JWT
def generar_token(usuario: Usuario) -> str:
    """Genera un token JWT para el usuario."""
    payload = {
        'id': usuario.id,
        'username': usuario.username,
        'rol': usuario.rol,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)  # Token expira en 24 horas
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')

# Decorador para proteger rutas
def token_required(f):
    """Decorador para proteger rutas que requieren autenticación."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            logger.warning("Token de autenticación faltante")
            raise Unauthorized("Token de autenticación requerido")

        try:
            token = token.split(" ")[1] #Bearer
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            usuario = Usuario.query.filter_by(id=data['id']).first()
            if not usuario:
                raise Unauthorized("Usuario no encontrado")
            g.usuario = usuario  # Guardar el usuario en el contexto global de Flask
        except jwt.ExpiredSignatureError:
            logger.warning("Token de autenticación expirado")
            raise Unauthorized("Token de autenticación expirado")
        except jwt.InvalidTokenError:
            logger.warning("Token de autenticación inválido")
            raise Unauthorized("Token de autenticación inválido")
        except Unauthorized as e:
            raise e
        except Exception as e:
            logger.error(f"Error al decodificar el token: {e}", exc_info=True)
            raise InternalServerError("Error interno del servidor")

        return f(*args, **kwargs)
    return decorated

# Decorador para restringir el acceso a roles específicos
def rol_required(rol_esperado: str):
    """Decorador para restringir el acceso a rutas según el rol del usuario."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'usuario') or g.usuario.rol != rol_esperado:
                logger.warning(f"Acceso no autorizado: se requiere el rol '{rol_esperado}'")
                raise Unauthorized(f"Se requiere el rol '{rol_esperado}' para acceder a este recurso")
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Blueprint para autenticación y usuarios
auth_bp = Blueprint('auth', __name__)
usuario_bp = Blueprint('usuarios', __name__)  # Blueprint para usuarios

# Blueprint para proyectos
proyecto_bp = Blueprint('proyectos', __name__)

# Rutas de autenticación
@auth_bp.route('/registrar', methods=['POST'])
def registrar_usuario():
    """
    Registra un nuevo usuario.
    ---
    tags:
      - Autenticación
    parameters:
      - in: body
        name: body
        description: Datos del usuario a registrar.
        required: true
        schema:
          type: object
          required:
            - username
            - password
          properties:
            username:
              type: string
              minLength: 4
              maxLength: 80
            password:
              type: string
              minLength: 8
    responses:
      201:
        description: Usuario registrado correctamente.
        schema:
          type: object
          properties:
            mensaje:
              type: string
            usuario:
              $ref: '#/definitions/Usuario'
      400:
        description: Datos inválidos.
      409:
        description: El nombre de usuario ya existe.
      500:
        description: Error en el servidor.
    definitions:
      Usuario:
        type: object
        properties:
          id:
            type: integer
          username:
            type: string
          rol:
            type: string
    """
    try:
        data = request.get_json()
        if not data:
            logger.warning("Petición inválida: no se proporcionaron datos")
            raise BadRequest("No se proporcionaron datos")

        username = data.get('username')
        password = data.get('password')

        if not username or not isinstance(username, str) or not (4 <= len(username.strip()) <= 80):
            logger.warning("Petición inválida: el nombre de usuario debe tener entre 4 y 80 caracteres")
            raise BadRequest("El nombre de usuario debe tener entre 4 y 80 caracteres")

        if not password or not isinstance(password, str) or len(password.strip()) < 8:
            logger.warning("Petición inválida: la contraseña debe tener al menos 8 caracteres")
            raise BadRequest("La contraseña debe tener al menos 8 caracteres")

        if Usuario.query.filter_by(username=username).first():
            logger.warning(f"El nombre de usuario '{username}' ya está en uso")
            raise IntegrityError(f"El nombre de usuario '{username}' ya está en uso")

        nuevo_usuario = Usuario(username=username)
        nuevo_usuario.set_password(password)
        db.session.add(nuevo_usuario)
        db.session.commit()
        logger.info(f"Usuario registrado correctamente: {nuevo_usuario}")
        return jsonify({
            "mensaje": "Usuario registrado correctamente",
            "usuario": nuevo_usuario.to_dict()
        }), 201

    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
    except IntegrityError as e:
        db.session.rollback()
        return jsonify({"error": "Ya existe un usuario con este nombre de usuario"}), 409
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error("Error en la base de datos al registrar usuario", exc_info=True)
        return jsonify({"error": "Error en la base de datos"}), 500
    except Exception as e:
        logger.error("Error inesperado al registrar usuario", exc_info=True)
        return jsonify({"error": "Error interno del servidor"}), 500

@auth_bp.route('/login', methods=['POST'])
def iniciar_sesion():
    """
    Inicia sesión de un usuario y devuelve un token JWT.
    ---
    tags:
      - Autenticación
    parameters:
      - in: body
        name: body
        description: Credenciales del usuario.
        required: true
        schema:
          type: object
          required:
            - username
            - password
          properties:
            username:
              type: string
            password:
              type: string
    responses:
      200:
        description: Inicio de sesión exitoso.
        schema:
          type: object
          properties:
            mensaje:
              type: string
            token:
              type: string
            usuario:
              $ref: '#/definitions/Usuario'
      400:
        description: Datos inválidos.
      401:
        description: Credenciales inválidas.
      500:
        description: Error en el servidor.
    """
    try:
        data = request.get_json()
        if not data:
            logger.warning("Petición inválida: no se proporcionaron datos")
            raise BadRequest("No se proporcionaron datos")

        username = data.get('username')
        password = data.get('password')

        if not username or not isinstance(username, str):
            logger.warning("Petición inválida: el nombre de usuario debe ser una cadena")
            raise BadRequest("El nombre de usuario debe ser una cadena")

        if not password or not isinstance(password, str):
            logger.warning("Petición inválida: la contraseña debe ser una cadena")
            raise BadRequest("La contraseña debe ser una cadena")

        usuario = Usuario.query.filter_by(username=username).first()
        if not usuario or not usuario.check_password(password):
            logger.warning(f"Credenciales inválidas para el usuario '{username}'")
            raise Unauthorized("Credenciales inválidas")

        token = generar_token(usuario)
        logger.info(f"Inicio de sesión exitoso para el usuario: {usuario}")
        return jsonify({
            "mensaje": "Inicio de sesión exitoso",
            "token": token,
            "usuario": usuario.to_dict()
        }), 200

    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
    except Unauthorized as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        logger.error("Error inesperado al iniciar sesión", exc_info=True)
        return jsonify({"error": "Error interno del servidor"}), 500

# Rutas para usuarios (ejemplo, protegidas con autenticación y autorización)
@usuario_bp.route('', methods=['GET'])
@token_required
@rol_required('admin')  # Solo los administradores pueden listar usuarios
def obtener_usuarios():
    """
    Obtiene la lista de usuarios (solo para administradores).
    ---
    tags:
      - Usuarios
    security:
      - BearerAuth: []
    responses:
      200:
        description: Lista de usuarios.
        schema:
          type: array
          items:
            $ref: '#/definitions/Usuario'
      401:
        description: Autenticación requerida.
      403:
        description: Acceso no autorizado.
      500:
        description: Error en el servidor.
    """
    try:
        usuarios = Usuario.query.all()
        return jsonify([usuario.to_dict() for usuario in usuarios]), 200
    except Exception as e:
        logger.error("Error inesperado al obtener usuarios", exc_info=True)
        return jsonify({"error": "Error interno del servidor"}), 500



# Rutas para proyectos
@proyecto_bp.route("", methods=["POST"])
@token_required #Protegemos la ruta
def agregar_proyecto():
    """
    Agrega un nuevo proyecto.
    ---
    tags:
      - Proyectos
    security:
      - BearerAuth: []
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
              minLength: 1
              maxLength: 100
            descripcion:
              type: string
              minLength: 1
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
        if not data:
            logger.warning("Petición inválida: no se proporcionaron datos")
            raise BadRequest("No se proporcionaron datos")

        titulo = data.get('titulo')
        descripcion = data.get('descripcion')

        if not titulo or not isinstance(titulo, str) or len(titulo.strip()) < 1 or len(titulo.strip()) > 100:
            logger.warning("Petición inválida: el título debe ser una cadena de entre 1 y 100 caracteres")
            raise BadRequest("El título debe ser una cadena de entre 1 y 100 caracteres")

        if not descripcion or not isinstance(descripcion, str) or len(descripcion.strip()) < 1:
            logger.warning("Petición inválida: la descripción debe ser una cadena de al menos 1 carácter")
            raise BadRequest("La descripción debe ser una cadena de al menos 1 carácter")

        proyecto = Proyecto(titulo=titulo, descripcion=descripcion, usuario_id=g.usuario.id) #Asignamos el usuario
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
        logger.error("Error de integridad en la base de datos al agregar proyecto: el título ya existe", exc_info=True)
        return jsonify({"error": "Ya existe un proyecto con este título"}), 409
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
        minimum: 1
      - name: per_page
        in: query
        type: integer
        description: Número de proyectos por página (por defecto 10).
        minimum: 1
        maximum: 100  # Añadido máximo por página
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
                $ref: '#/definitions/Proyecto'
      500:
        description: Error en el servidor.
    """
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)

        if page < 1:
            raise BadRequest("El número de página debe ser mayor o igual a 1")
        if per_page < 1 or per_page > 100:
            raise BadRequest("El número de proyectos por página debe estar entre 1 y 100")

        pagination = Proyecto.query.paginate(page=page, per_page=per_page, error_out=False)
        proyectos = [proyecto.to_dict() for proyecto in pagination.items]

        response = {
            "total": pagination.total,
            "page": page,
            "pages": pagination.pages,
            "per_page": per_page,
            "data": proyectos
        }
        return jsonify(response)

    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
    except SQLAlchemyError as e:
        logger.error("Error al obtener proyectos desde la base de datos", exc_info=True)
        return jsonify({"error": "Error al acceder a la base de datos"}), 500
    except Exception as e:
        logger.error("Error inesperado al obtener proyectos", exc_info=True)
        return jsonify({"error": "Error interno del servidor"}), 500

@proyecto_bp.route("/<int:id>", methods=["GET"])
def obtener_proyecto(id: int):
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
        minimum: 1
    responses:
      200:
        description: Proyecto obtenido correctamente.
        schema:
          $ref: '#/definitions/Proyecto'
      404:
        description: Proyecto no encontrado.
      500:
        description: Error en el servidor.
    """
    try:
        if id < 1:
            raise BadRequest("El ID del proyecto debe ser un entero positivo")
        proyecto = Proyecto.query.get_or_404(id)
        return jsonify(proyecto.to_dict())

    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
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
@token_required
def actualizar_proyecto(id: int):
    """
    Actualiza un proyecto existente.
    ---
    tags:
      - Proyectos
    security:
      - BearerAuth: []
    parameters:
      - name: id
        in: path
        type: integer
        required: true
        description: ID del proyecto a actualizar.
        minimum: 1
      - in: body
        name: body
        description: Datos para actualizar el proyecto.
        required: true
        schema:
          type: object
          properties:
            titulo:
              type: string
              minLength: 1
              maxLength: 100
            descripcion:
              type: string
              minLength: 1
    responses:
      200:
        description: Proyecto actualizado correctamente.
        schema:
          $ref: '#/definitions/Proyecto'
      400:
        description: Datos inválidos.
      403:
        description: No tiene permisos para actualizar este proyecto.
      404:
        description: Proyecto no encontrado.
      500:
        description: Error en el servidor.
    """
    try:
        if id < 1:
            raise BadRequest("El ID del proyecto debe ser un entero positivo")

        data = request.get_json()
        if not data:
            logger.warning(f"Petición inválida al actualizar proyecto {id}: no se proporcionaron datos")
            raise BadRequest("No se proporcionaron datos para actualizar")

        titulo = data.get('titulo')
        descripcion = data.get('descripcion')

        if titulo is not None and (not isinstance(titulo, str) or len(titulo.strip()) < 1 or len(titulo.strip()) > 100):
            logger.warning(f"Petición inválida al actualizar proyecto {id}: el título debe ser una cadena de entre 1 y 100 caracteres")
            raise BadRequest("El título debe ser una cadena de entre 1 y 100 caracteres")

        if descripcion is not None and (not isinstance(descripcion, str) or len(descripcion.strip()) < 1):
            logger.warning(f"Petición inválida al actualizar proyecto {id}: la descripción debe ser una cadena de al menos 1 carácter")
            raise BadRequest("La descripción debe ser una cadena de al menos 1 carácter")

        proyecto = Proyecto.query.get_or_404(id)

        if proyecto.usuario_id != g.usuario.id:
            raise Unauthorized("No tiene permisos para actualizar este proyecto")

        if "titulo" in data:
            proyecto.titulo = titulo
        if "descripcion" in data:
            proyecto.descripcion = descripcion

        db.session.commit()
        logger.info(f"Proyecto actualizado correctamente: {proyecto}")
        return jsonify(proyecto.to_dict())

    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
    except Unauthorized as e:
        return jsonify({"error": str(e)}), 403
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
@token_required
def eliminar_proyecto(id: int):
    """
    Elimina un proyecto existente.
    ---
    tags:
      - Proyectos
    security:
      - BearerAuth: []
    parameters:
      - name: id
        in: path
        type: integer
        required: true
        description: ID del proyecto a eliminar.
        minimum: 1
    responses:
      200:
        description: Proyecto eliminado correctamente.
        schema:
          type: object
          properties:
            mensaje:
              type: string
      403:
        description: No tiene permisos para eliminar este proyecto.
      404:
        description: Proyecto no encontrado.
      500:
        description: Error en el servidor.
    """
    try:
        if id < 1:raise BadRequest("El ID del proyecto debe ser un entero positivo")
        proyecto = Proyecto.query.get_or_404(id)

        if proyecto.usuario_id != g.usuario.id:
            raise Unauthorized("No tiene permisos para eliminar este proyecto")

        db.session.delete(proyecto)
        db.session.commit()
        logger.info(f"Proyecto eliminado correctamente: {proyecto}")
        return jsonify({"mensaje": "Proyecto eliminado correctamente"})

    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
    except Unauthorized as e:
        return jsonify({"error": str(e)}), 403
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



# Registro de Blueprints en la aplicación
app.register_blueprint(proyecto_bp, url_prefix="/proyectos")
app.register_blueprint(auth_bp, url_prefix="/auth")
app.register_blueprint(usuario_bp, url_prefix="/usuarios") #Registramos el nuevo blueprint


# Manejo personalizado de errores HTTP
@app.errorhandler(BadRequest)
def bad_request(e: BadRequest):
    """Manejador para errores 400 Bad Request."""
    logger.warning(f"Solicitud incorrecta: {e}")
    return jsonify({"error": str(e)}), 400

@app.errorhandler(NotFound)
def not_found(e: NotFound):
    """Manejador para errores 404 Not Found."""
    logger.warning(f"Recurso no encontrado: {e}")
    return jsonify({"error": "Recurso no encontrado"}), 404

@app.errorhandler(Unauthorized)
def unauthorized(e: Unauthorized):
    """Manejador para errores 401 Unauthorized."""
    logger.warning(f"No autorizado: {e}")
    return jsonify({"error": str(e)}), 401

@app.errorhandler(InternalServerError)
def internal_server_error(e: InternalServerError):
    """Manejador para errores 500 Internal Server Error."""
    logger.error(f"Error interno del servidor: {e}", exc_info=True)
    return jsonify({"error": "Error interno del servidor"}), 500

@app.errorhandler(SQLAlchemyError)
def database_error(e: SQLAlchemyError):
    """Manejador para errores de SQLAlchemy."""
    db.session.rollback()
    logger.error(f"Error de base de datos: {e}", exc_info=True)
    return jsonify({"error": "Error en la base de datos"}), 500

@app.errorhandler(Exception)
def general_error(e: Exception):
    """Manejador para errores generales no manejados."""
    logger.error(f"Error general no manejado: {e}", exc_info=True)
    return jsonify({"error": "Ha ocurrido un error inesperado"}), 500

# Función para crear la base de datos y datos de prueba (solo para desarrollo)
def crear_base_de_datos_y_datos_de_prueba():
    """Crea la base de datos y agrega datos de prueba."""
    with app.app_context():
        db.create_all()
        # Crear usuario administrador por defecto si no existe
        if not Usuario.query.filter_by(username='admin').first():
            admin_user = Usuario(username='admin')
            admin_user.set_password('admin123')  # ¡Cambiar esto en producción!
            admin_user.rol = 'admin'
            db.session.add(admin_user)
            db.session.commit()
            logger.info("Usuario administrador creado")

        # Crear algunos proyectos de ejemplo
        if not Proyecto.query.first():
            usuario_admin = Usuario.query.filter_by(username='admin').first()
            proyecto1 = Proyecto(titulo='Proyecto 1', descripcion='Descripción del Proyecto 1', usuario_id=usuario_admin.id)
            proyecto2 = Proyecto(titulo='Proyecto 2', descripcion='Descripción del Proyecto 2', usuario_id=usuario_admin.id)
            db.session.add_all([proyecto1, proyecto2])
            db.session.commit()
            logger.info("Proyectos de ejemplo creados")
        logger.info("Base de datos inicializada")

# Función para ejecutar las pruebas
def ejecutar_pruebas():
    """Ejecuta las pruebas unitarias y de integración."""
    result = pytest.main(['tests/'])  # Ejecuta las pruebas en el directorio 'tests'
    if result == 0:
        logger.info("Todas las pruebas pasaron")
    else:
        logger.error("Algunas pruebas fallaron")

if __name__ == '__main__':
    # Crear la base de datos y los datos de prueba solo si la aplicación se ejecuta directamente
    crear_base_de_datos_y_datos_de_prueba()
    ejecutar_pruebas() #Ejecutamos las pruebas
    # Iniciar el servidor de desarrollo de Flask
    app.run(debug=True, host='0.0.0.0', port=5000)

