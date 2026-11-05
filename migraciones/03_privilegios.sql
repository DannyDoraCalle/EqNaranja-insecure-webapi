-- Parche 7: minimo privilegio para el usuario de la API
-- Ejecutar como root. La API solo necesita leer y escribir filas,
-- no crear, borrar ni alterar tablas.
REVOKE ALL PRIVILEGES ON webapps.* FROM 'udbwebaps'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON webapps.* TO 'udbwebaps'@'localhost';
FLUSH PRIVILEGES;
