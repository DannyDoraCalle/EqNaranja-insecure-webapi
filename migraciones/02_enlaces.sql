-- Parche 6: enlaces de descarga aleatorios y temporales
create table if not exists EnlaceDescarga(
	llave varchar(64) primary key,
	id_Imagen int not null,
	expira datetime not null,
	CONSTRAINT FK_ED_I FOREIGN KEY (id_Imagen) REFERENCES Imagen(id) ON DELETE CASCADE
)ENGINE=InnoDB;
