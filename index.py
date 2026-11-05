import json
import secrets
import mysql.connector
import bcrypt
import pyotp
import base64
import zlib
from pathlib import Path
from bottle import route, run, post, request, static_file, BaseRequest, abort

# Minutos que dura un enlace de descarga
VIGENCIA_ENLACE = 5

# Tamaño maximo de la imagen ya descomprimida
MAX_IMAGEN = 5 * 1024 * 1024
# Bottle rechaza cuerpos de mas de 100 KB por defecto; se permite lo
# necesario para una imagen comprimida y codificada en base64
BaseRequest.MEMFILE_MAX = 8 * 1024 * 1024

# Lista blanca: extension permitida -> firmas (magic bytes) validas
FIRMAS = {
	"png":  [b"\x89PNG\r\n\x1a\n"],
	"jpg":  [b"\xff\xd8\xff"],
	"jpeg": [b"\xff\xd8\xff"],
	"gif":  [b"GIF87a", b"GIF89a"],
	"webp": [b"RIFF"],
}

def decodificarImagen(data, ext):
	"""data = base64( gzip( bytes de la imagen ) ). Regresa los bytes o None"""
	if not isinstance(data, str) or ext not in FIRMAS:
		return None
	try:
		comprimido = base64.b64decode(data, validate=True)
		# 16 + MAX_WBITS = formato gzip. Se limita la salida para evitar
		# "bombas" gzip que se expanden a gigas al descomprimirse
		d = zlib.decompressobj(16 + zlib.MAX_WBITS)
		datos = d.decompress(comprimido, MAX_IMAGEN + 1)
	except (ValueError, zlib.error):
		return None
	if not d.eof or d.unconsumed_tail or len(datos) > MAX_IMAGEN or not datos:
		return None
	# El contenido real debe coincidir con la extension declarada
	if not any(datos.startswith(f) for f in FIRMAS[ext]):
		return None
	if ext == "webp" and datos[8:12] != b"WEBP":
		return None
	return datos



def loadDatabaseSettings(pathjs):
	pathjs = Path(pathjs)
	sjson = False
	if pathjs.exists():
		with pathjs.open() as data:
			sjson = json.load(data)
	return sjson
	
"""
function loadDatabaseSettings(pathjs):
	string = file_get_contents(pathjs);
	json_a = json_decode(string, true);
	return json_a;

"""
# Minutos que dura un token de sesion
VIGENCIA_TOKEN = 30

def getToken():
	# secrets usa el generador criptografico del sistema operativo;
	# random no sirve para esto porque su salida se puede predecir
	return secrets.token_urlsafe(32)

def validarToken(db, TKN):
	"""Regresa el id del usuario si el token existe y no ha expirado, si no None"""
	if not isinstance(TKN, str) or not TKN:
		return None
	with db.cursor() as cursor:
		cursor.execute(
			'select id_Usuario from AccesoToken where token = %s and fecha > now() - interval %s minute',
			(TKN, VIGENCIA_TOKEN))
		R = cursor.fetchall()
	return R[0][0] if R else None

"""
*/ 
# Registro
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 *		"uname": "XXX",
 *		"email": "XXX",
 * 		"password": "XXX"
 * 
 * */
"""
@post('/Registro')
def Registro():
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)
	####/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	R = 'uname' in request.json and 'email' in request.json and 'password' in request.json
	if not R:
		return {"R":-1}
	uname = str(request.json["uname"]).strip()
	email = str(request.json["email"]).strip().lower()
	password = str(request.json["password"])
	# bcrypt solo usa los primeros 72 bytes; se exige minimo 8 caracteres
	if not uname or "@" not in email or len(password) < 8 or len(password.encode()) > 72:
		return {"R":-1}
	# Hash con bcrypt: sal aleatoria por usuario y costo configurable
	hashpw = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
	# Secreto TOTP del usuario (segundo factor, RFC 6238)
	secreto = pyotp.random_base32()
	R = False
	try:
		with db.cursor() as cursor:
			cursor.execute('insert into Usuario (uname, email, password, totp_secret) values(%s,%s,%s,%s)',
				(uname, email, hashpw, secreto))
			R = cursor.lastrowid
			db.commit()
		db.close()
	except Exception as e:
		print(e) 
		return {"R":-2}
	# La URI se convierte en QR para Google Authenticator, Authy, etc.
	# Solo se entrega una vez, al registrarse
	uri = pyotp.TOTP(secreto).provisioning_uri(name=uname, issuer_name="WebAPI")
	return {"R":0,"D":R,"totp":uri}




"""
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 *		"uname": "XXX",
 * 		"password": "XXX",
 * 		"otp": "123456"   (codigo TOTP de la app autenticadora)
 * 
 * 
 * Debe retornar un Token 
 * */
"""

@post('/Login')
def Login():
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)
	###/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	######/
	R = 'uname' in request.json  and 'password' in request.json and 'otp' in request.json
	if not R:
		return {"R":-1}
	
	# TODO validar correo en json
	# TODO Control de error de la DB
	R = False
	try:
		with db.cursor() as cursor:
			cursor.execute('Select id, password, totp_secret from  Usuario where uname = %s', (str(request.json["uname"]),))
			R = cursor.fetchall()
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
	
	
	# Comparar la contraseña contra el hash bcrypt guardado
	valido = False
	if R:
		try:
			valido = bcrypt.checkpw(str(request.json["password"]).encode(), R[0][1].encode())
		except ValueError:
			# Hash viejo (MD5) u otro formato invalido
			valido = False
	# Segundo factor: codigo de 6 digitos de la app autenticadora.
	# valid_window=1 tolera 30 s de desfase de reloj
	if valido:
		valido = bool(R[0][2]) and pyotp.TOTP(R[0][2]).verify(str(request.json["otp"]), valid_window=1)
	if not valido:
		db.close()
		return {"R":-3}
	
	T = getToken();
	
	try:
		with db.cursor() as cursor:
			cursor.execute('Delete from AccesoToken where id_Usuario = %s', (R[0][0],))
			cursor.execute('insert into AccesoToken values(%s,%s,now())', (R[0][0], T))
			db.commit()
			db.close()
			return {"R":0,"D":T}
	except Exception as e:
		print(e)
		db.close()
		return {"R":-4}

"""
/*
 * Este subir imagen recibe un JSON con el siguiente formato
 * 
 * 
 * 		"token: "XXX"
 *		"name": "XXX",
 * 		"data": "XXX",   base64 de la imagen comprimida con gzip
 * 		"ext": "png"     png, jpg, jpeg, gif o webp
 * 
 * 
 * Debe retornar codigo de estado
 * */
"""
@post('/Imagen')
def Imagen():
	#Directorio
	img = Path('img')
	if not img.exists():
		img.mkdir()
	
	###/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	######/
	R = 'name' in request.json  and 'data' in request.json and 'ext' in request.json  and 'token' in request.json
	if not R:
		return {"R":-1}
	nombre = str(request.json['name']).strip()[:250]
	ext = str(request.json['ext']).strip().lower()
	if not nombre:
		return {"R":-1}
	
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)

	# Validar si el usuario esta en la base de datos
	TKN = request.json['token'];
	
	try:
		id_Usuario = validarToken(db, TKN)
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
	if id_Usuario is None:
		db.close()
		return {"R":-4}
	
	datos = decodificarImagen(request.json['data'], ext)
	if datos is None:
		db.close()
		return {"R":-5}
	
	# Nombre de archivo aleatorio generado por el servidor; el usuario
	# ya no controla ninguna parte de la ruta
	ruta = 'img/' + secrets.token_hex(16) + '.' + ext
	with open(ruta, "wb") as imagen:
		imagen.write(datos)
	
	# Guardar info del archivo en la base de datos
	try:
		with db.cursor() as cursor:
			cursor.execute('insert into Imagen values(null,%s,%s,%s)', (nombre, ruta, id_Usuario))
			idImagen = cursor.lastrowid
			db.commit()
			db.close()
			return {"R":0,"D":idImagen}
	except Exception as e: 
		Path(ruta).unlink(missing_ok=True)
		print(e)
		db.close()
		return {"R":-3}
	
"""
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 * 		"token: "XXX",
 * 		"id": "XXX"
 * 
 * 
 * Debe retornar una URL aleatoria y temporal para descargar la imagen
 * (solo si la imagen pertenece al usuario del token)
 * */
"""

@post('/Descargar')
def Descargar():
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)
	
	
	###/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	######/
	R = 'token' in request.json and 'id' in request.json  
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}
	
	# TODO validar correo en json
	# Comprobar que el usuario sea valido
	TKN = request.json['token'];
	try:
		idImagen = int(request.json['id'])
	except (TypeError, ValueError):
		return {"R":-1}
	
	try:
		id_Usuario = validarToken(db, TKN)
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
	if id_Usuario is None:
		db.close()
		return {"R":-4}

	
	
	# Buscar la imagen SOLO entre las del usuario dueño del token
	# y generar un enlace aleatorio que caduca
	llave = secrets.token_urlsafe(32)
	try:
		with db.cursor() as cursor:
			cursor.execute('Select id from  Imagen where id = %s and id_Usuario = %s', (idImagen, id_Usuario))
			R = cursor.fetchall()
			if not R:
				db.close()
				return {"R":-3}
			cursor.execute('delete from EnlaceDescarga where expira < now()')
			cursor.execute('insert into EnlaceDescarga values(%s,%s,now() + interval %s minute)',
				(llave, idImagen, VIGENCIA_ENLACE))
			db.commit()
		db.close()
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
	# request.urlparts respeta X-Forwarded-Proto, asi que detras de
	# Nginx la URL sale con https://
	base = request.urlparts.scheme + "://" + request.urlparts.netloc
	return {"R":0,"D":f"{base}/img/{llave}","expira_min":VIGENCIA_ENLACE}

"""
/*
 * GET /img/<llave>
 * Entrega la imagen si el enlace existe y no ha caducado
 * */
"""
@route('/img/<llave>')
def VerImagen(llave):
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)
	try:
		with db.cursor() as cursor:
			cursor.execute('select i.ruta from EnlaceDescarga e join Imagen i on i.id = e.id_Imagen '
				'where e.llave = %s and e.expira > now()', (llave,))
			R = cursor.fetchall()
	finally:
		db.close()
	if not R:
		abort(404, "Enlace inexistente o caducado")
	# root fija la carpeta img/: static_file no permite salir de ella
	resp = static_file(Path(R[0][0]).name, root=str(Path("img").resolve()))
	# Evita que el navegador "adivine" otro tipo de contenido
	resp.set_header("X-Content-Type-Options", "nosniff")
	return resp

if __name__ == '__main__':
    # debug=False: los errores ya no muestran codigo ni trazas al cliente
    run(host='localhost', port=8080, debug=False)
