from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import logging
import json
import spacy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Cargar modelo de spaCy
nlp = spacy.load("es_core_news_sm")

# Modelos de la Base de Datos
class Proyecto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text, nullable=False)

class DocumentoProcesado(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    texto_original = db.Column(db.Text, nullable=False)
    resumen = db.Column(db.Text, nullable=False)
    conceptos_clave = db.Column(db.Text, nullable=False)  # JSON string
    conexiones = db.Column(db.Text, nullable=False)  # JSON string
    proyecto_id = db.Column(db.Integer, db.ForeignKey('proyecto.id'), nullable=True)

    proyecto = db.relationship('Proyecto', backref=db.backref('documentos', lazy=True))

# 📌 Ruta para Procesar un Documento
@app.route("/procesar_documento", methods=['POST'])
def procesar_documento():
    try:
        datos = request.get_json()
        if not datos or "texto" not in datos:
            return jsonify({"error": "Se requiere un texto para procesar"}), 400

        texto = datos["texto"]
        doc = nlp(texto)

        tokens = [{"texto": token.text, "lema": token.lemma_, "tipo": token.pos_} for token in doc]
        entidades = [{"texto": entidad.text, "tipo": entidad.label_} for entidad in doc.ents]

        resumen = " ".join([sent.text for sent in doc.sents if any(token.pos_ in ["NOUN", "PROPN"] for token in sent)])
        conceptos_clave = list(set([token.lemma_ for token in doc if token.pos_ in ["NOUN", "PROPN"]] + [entidad.text for entidad in doc.ents]))

        conexiones = [{"desde": token.text, "hacia": hijo.text, "relacion": hijo.dep_} for token in doc for hijo in token.children if hijo.pos_ in ["NOUN", "PROPN"]]

        respuesta = {
            "tokens": tokens,
            "entidades": entidades,
            "resumen": resumen,
            "conceptos_clave": conceptos_clave,
            "conexiones": conexiones
        }
        return jsonify(respuesta), 200
    except Exception as e:
        logger.exception("Error al procesar el documento: %s", e)
        return jsonify({"error": str(e)}), 500

# 📌 Ruta para Guardar un Documento Procesado
@app.route("/guardar_documento", methods=['POST'])
def guardar_documento():
    try:
        datos = request.get_json()
        if not datos or "texto" not in datos or "resumen" not in datos or "conceptos_clave" not in datos or "conexiones" not in datos:
            return jsonify({"error": "Faltan datos requeridos"}), 400

        nuevo_documento = DocumentoProcesado(
            texto_original=datos["texto"],
            resumen=datos["resumen"],
            conceptos_clave=json.dumps(datos["conceptos_clave"]),
            conexiones=json.dumps(datos["conexiones"]),
            proyecto_id=datos.get("proyecto_id")
        )
        db.session.add(nuevo_documento)
        db.session.commit()

        return jsonify({"mensaje": "Documento procesado guardado correctamente", "documento_id": nuevo_documento.id}), 201
    except Exception as e:
        logger.exception("Error al guardar el documento procesado: %s", e)
        return jsonify({"error": str(e)}), 500

# 📌 Ruta para Listar Documentos con Filtros y Paginación
@app.route("/listar_documentos", methods=["GET"])
def listar_documentos():
    try:
        proyecto_id = request.args.get("proyecto_id")
        palabra_clave = request.args.get("palabra_clave")
        pagina = request.args.get("pagina", default=1, type=int)
        tamano_pagina = request.args.get("tamano_pagina", default=10, type=int)

        consulta = DocumentoProcesado.query

        if proyecto_id:
            consulta = consulta.filter_by(proyecto_id=proyecto_id)
        if palabra_clave:
            consulta = consulta.filter(DocumentoProcesado.texto_original.contains(palabra_clave))

        documentos_paginados = consulta.paginate(page=pagina, per_page=tamano_pagina, error_out=False).items

        lista_documentos = [
            {
                "id": doc.id,
                "texto_original": doc.texto_original,
                "resumen": doc.resumen,
                "conceptos_clave": json.loads(doc.conceptos_clave) if doc.conceptos_clave else [],
                "conexiones": json.loads(doc.conexiones) if doc.conexiones else [],
                "proyecto_id": doc.proyecto_id
            }
            for doc in documentos_paginados
        ]

        return jsonify({
            "total_documentos": consulta.count(),
            "pagina_actual": pagina,
            "tamano_pagina": tamano_pagina,
            "documentos": lista_documentos
        }), 200

    except Exception as e:
        logger.exception("Error al listar documentos procesados: %s", e)
        return jsonify({"error": "No se pudo obtener la lista de documentos", "detalle": str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
