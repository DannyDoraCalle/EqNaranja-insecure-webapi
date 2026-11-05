-- Parche 9: registro de intentos fallidos de inicio de sesion
create table if not exists IntentoFallido(
	id int AUTO_INCREMENT primary key,
	uname varchar(50) not null,
	fecha datetime not null,
	index IX_IF_U (uname, fecha)
)ENGINE=InnoDB;
