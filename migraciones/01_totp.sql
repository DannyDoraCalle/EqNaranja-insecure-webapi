-- Parche 4: secreto TOTP (segundo factor) por usuario
ALTER TABLE Usuario ADD COLUMN totp_secret varchar(64) NULL;
