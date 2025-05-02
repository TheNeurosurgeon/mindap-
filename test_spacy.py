import spacy

# Cargar el modelo de idioma en español o inglés (según tu descarga)
# Si usas español:
nlp = spacy.load("es_core_news_sm")

# Si usas inglés:
# nlp = spacy.load("en_core_web_sm")

# Texto de ejemplo (puedes cambiarlo por otro)
texto = "te amo mi amor preciosa."

# Procesar el texto con spaCy
doc = nlp(texto)

# Analizar palabras clave (tokens)
print("Palabras clave (tokens):")
for token in doc:
    print(f"- {token.text} (Tipo: {token.pos_}, Lema: {token.lemma_})")

# Identificar entidades nombradas (como personas, lugares, organizaciones, etc.)
print("\nEntidades nombradas:")
for entidad in doc.ents:
    print(f"- {entidad.text} (Tipo: {entidad.label_})")
