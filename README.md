# GruposEstudio
CREATE TABLE solicitudes (
    solicitud_id SERIAL PRIMARY KEY,
    usuario_id INT NOT NULL,
    tipo_servicio VARCHAR(50) NOT NULL,
    materia VARCHAR(255) NOT NULL,
    tema_interes TEXT,
    fecha_reunion DATE NOT NULL, -- Nuevo campo para la fecha de la reunión
    fecha_solicitud TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);