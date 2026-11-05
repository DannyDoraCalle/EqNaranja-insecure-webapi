import json
import secrets
import mysql.connector
import bcrypt
import base64
import shutil
from datetime import datetime
from pathlib import Path
from bottle import route, run, template, post, request, static_file



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
	R = False
	try:
		with db.cursor() as cursor:
			cursor.execute('insert into Usuario values(null,%s,%s,%s)', (uname, email, hashpw))
			R = cursor.lastrowid
			db.commit()
		db.close()
	except Exception as e:
		print(e) 
		return {"R":-2}
	return {"R":0,"D":R}




"""
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 *		"uname": "XXX",
 * 		"password": "XXX"
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
	R = 'uname' in request.json  and 'password' in request.json
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}
	
	# TODO validar correo en json
	# TODO Control de error de la DB
	R = False
	try:
		with db.cursor() as cursor:
			cursor.execute('Select id, password from  Usuario where uname = %s', (str(request.json["uname"]),))
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
 * 		"data": "XXX",
 * 		"ext": "PNG"
 * 
 * 
 * Debe retornar codigo de estado
 * */
"""
@post('/Imagen')
def Imagen():
	#Directorio
	tmp = Path('tmp')
	if not tmp.exists():
		tmp.mkdir()
	img = Path('img')
	if not img.exists():
		img.mkdir()
	
	###/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	######/
	R = 'name' in request.json  and 'data' in request.json and 'ext' in request.json  and 'token' in request.json
	# TODO checar si estan vacio los elementos del json
	if not R:
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
	
	with open(f'tmp/{id_Usuario}',"wb") as imagen:
		imagen.write(base64.b64decode(request.json['data'].encode()))
	
	############################
	############################
	# Guardar info del archivo en la base de datos
	try:
		with db.cursor() as cursor:
			cursor.execute('insert into Imagen values(null,%s,"img/",%s)', (request.json["name"], id_Usuario))
			idImagen = cursor.lastrowid
			cursor.execute('update Imagen set ruta = %s where id = %s', ('img/'+str(idImagen)+'.'+str(request.json['ext']), idImagen))
			db.commit()
			# Mover archivo a su nueva locacion
			shutil.move('tmp/'+str(id_Usuario),'img/'+str(idImagen)+'.'+str(request.json['ext']))
			return {"R":0,"D":idImagen}
	except Exception as e: 
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
 * Debe retornar un Token 
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
	idImagen = request.json['id'];
	
	try:
		id_Usuario = validarToken(db, TKN)
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
	if id_Usuario is None:
		db.close()
		return {"R":-4}

	
	
	# Buscar imagen y enviarla
	
	try:
		with db.cursor() as cursor:
			cursor.execute('Select name,ruta from  Imagen where id = %s', (idImagen,))
			R = cursor.fetchall()
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-3}
	print(Path("img").resolve(),R[0][1])
	return static_file(R[0][1],Path(".").resolve())

if __name__ == '__main__':
    run(host='localhost', port=8080, debug=True)
