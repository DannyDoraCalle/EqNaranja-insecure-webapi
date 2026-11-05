-- Parche 10: uname y email deben ser unicos cada uno por separado.
-- La restriccion original U_U (uname, email) solo impedia repetir la PAREJA.
--
-- ANTES de ejecutar, revisa si ya hay duplicados:
--   select uname, count(*) from Usuario group by uname having count(*) > 1;
--   select email, count(*) from Usuario group by email having count(*) > 1;
-- Si hay, borra los sobrantes (y sus filas en AccesoToken / Imagen) o el
-- ALTER fallara.
ALTER TABLE Usuario
	DROP INDEX U_U,
	ADD CONSTRAINT U_UNAME UNIQUE (uname),
	ADD CONSTRAINT U_EMAIL UNIQUE (email);
