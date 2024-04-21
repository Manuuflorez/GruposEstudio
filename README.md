# GruposEstudio
Tabla de usuarios

CREATE TABLE public.users (
	id bigserial NOT NULL,
	"name" varchar(200) NOT NULL,
	lastname varchar(200) NOT NULL,
	document_type varchar(2) NOT NULL,
	id_number varchar(20) NOT NULL,
	email varchar(200) NOT NULL,
	"program" varchar(200) NOT NULL,
	"password" varchar(200) NOT NULL,
	user_data jsonb NULL,
	CONSTRAINT users_pkey PRIMARY KEY (id)
);





Tabla de solicitudes

CREATE TABLE public.solicitudes (
	solicitud_id serial4 NOT NULL,
	tipo_servicio varchar(50) NOT NULL,
	materia varchar(255) NOT NULL,
	tema_interes text NULL,
	fecha_reunion date NOT NULL,
	fecha_solicitud timestamp DEFAULT CURRENT_TIMESTAMP NULL,
	user_data jsonb NULL,
	CONSTRAINT solicitudes_pkey PRIMARY KEY (solicitud_id)
);