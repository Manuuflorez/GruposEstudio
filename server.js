const express = require("express");
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
require("dotenv").config();
const app = express();

const PORT = process.env.PORT || 3000;

const initializePassport = require("./passportConfig");

initializePassport(passport);

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
// Parsea los detalles de un formulario
app.use(express.urlencoded({ extended: false }));

app.use(bodyParser.json());

app.use(bodyParser.urlencoded({ extended: true }));

app.set("view engine", "ejs");

app.use(
  session({
    // Clave que queremos mantener en secreto y que cifrará toda nuestra información
    secret: process.env.SESSION_SECRET,
    // ¿Deberíamos guardar nuestras variables de sesión si no ha habido cambios? No queremos hacerlo
    resave: false,
    // Guardar un valor vacío si no hay valor, lo cual no queremos hacer
    saveUninitialized: false,
    rolling: true, // Habilitar renovación de sesión en cada solicitud
    cookie: {
      maxAge: 60 * 60 * 1000 // Duración de la sesión en milisegundos (1 hora)
    }
  })
);
// Función dentro de passport que inicializa passport
app.use(passport.initialize());
// Almacena nuestras variables para que persistan en toda la sesión. Funciona con app.use(Session) arriba
app.use(passport.session());
app.use(flash());

app.get("/", (req, res) => {
  res.render("index");
});

app.get("/users/reset-password", (req, res) => {
  res.render("restablecerpass.ejs");
});

app.get('/users/reset-password/:token', (req, res) => {
  const { token } = req.params;
  res.render('restablecerpass-token', { token });
});

app.get("/users/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/users/profile", checkNotAuthenticated, (req, res) => {
  res.render("profile.ejs", { user: req.user });
});

// Endpoint para obtener las agendas de una publicación específica
app.get("/api/agendas-publicacion/:solicitud_id", async (req, res) => {
  const { solicitud_id } = req.params;
  try {
    const result = await pool.query(
      `SELECT user_name FROM agendas WHERE tema = (
         SELECT tema_interes FROM solicitudes WHERE solicitud_id = $1
       )`,
      [solicitud_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Error al obtener las agendas de la publicación:", err);
    res.status(500).send("Error al obtener las agendas de la publicación");
  }
});


app.get("/users/reservas/:id", async (req, res) => {
  try {
    const solicitudId = req.params.id;
    const result = await pool.query('SELECT * FROM solicitudes WHERE solicitud_id = $1', [solicitudId]);
    const solicitud = result.rows[0];

    if (!solicitud) {
      return res.status(404).send('Solicitud no encontrada');
    }

    res.render("reservas.ejs", { user: req.user, solicitud: solicitud });
  } catch (error) {
    console.error('Error fetching solicitud:', error);
    res.status(500).send('Error del servidor');
  }
});


app.get("/users/login", (req, res) => {
  const errors = req.flash('error');
  res.render("login.ejs", { errors: errors || [] });
});

app.get("/users/dashboard", checkNotAuthenticated, (req, res) => {
  res.render("dashboard", { user: req.user });
});

app.get("/users/logout", checkNotAuthenticated, (req, res) => {
  res.render("dashboard", { user: req.user });
});

app.get('/logout', (req, res) => {
  // Destruir la sesión
  req.session.destroy(err => {
    if (err) {
      console.error("Error al cerrar sesión:", err);
      return res.status(500).send("Error al cerrar sesión");
    }
    res.redirect('/users/login');
  });
});

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'manuuflorez1@gmail.com',
    pass: 'qslb timx xdni mogo'
  }
});

// Ruta para solicitar el restablecimiento de contraseña
app.post("/users/reset-password", async (req, res) => {
  const { email } = req.body;
  const token = crypto.randomBytes(20).toString('hex');

  try {
    await pool.query(
      "INSERT INTO password_resets (email, token) VALUES ($1, $2)",
      [email, token]
    );

    // Envía el correo electrónico con el token de restablecimiento
    const resetLink = `http://localhost:3000/users/reset-password/${token}`;
    const mailOptions = {
      from: 'manuuflorez1@gmail.com',
      to: email,
      subject: 'Solicitud de restablecimiento de contraseña para StudyCoop',
      text: `Has solicitado un restablecimiento de contraseña. Utiliza el siguiente enlace para restablecer tu contraseña: ${resetLink}`,
      html: `<p>Has solicitado un restablecimiento de contraseña. Utiliza el siguiente enlace para restablecer tu contraseña:</p><a href="${resetLink}">Restablecer Contraseña</a>`
    };

    await transporter.sendMail(mailOptions);
    res.json({ message: "¡Correo electrónico enviado para el restablecimiento de contraseña!" });
  } catch (error) {
    console.error("Error al solicitar el restablecimiento de contraseña:", error);
    res.status(500).json({ error: "Error al solicitar el restablecimiento de contraseña" });
  }
});



// Ruta para restablecer la contraseña
app.post("/users/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { password, confirm_password } = req.body;

  if (password !== confirm_password) {
    return res.status(400).json({ error: "Las contraseñas no coinciden" });
  }

  try {
    const result = await pool.query(
      "SELECT * FROM password_resets WHERE token = $1",
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: "Este enlace ya ha vencido, token no valido." });
    }

    const email = result.rows[0].email;
    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      "UPDATE users SET password = $1 WHERE email = $2",
      [hashedPassword, email]
    );

    // Elimina el token después de usarlo
    await pool.query(
      "DELETE FROM password_resets WHERE token = $1",
      [token]
    );

    res.json({ message:"¡Contraseña actualizada correctamente!"});
  } catch (error) {
    console.error("Error al actualizar la contraseña:", error);
    res.status(500).json({ error: "Error al actualizar la contraseña" });
  }
});

app.post("/users/register", async (req, res) => {
  let { name, lastname, document_type, id_number, email, program, password, password2 } = req.body;

  let errors = [];

  if (!name || !lastname || !document_type || !id_number || !email || !program || !password || !password2) {
    errors.push({ message: "Por favor completa todos los campos" });
  }

  if (password.length < 6) {
    errors.push({ message: "La contraseña debe tener al menos 6 caracteres" });
  }

  // Validación de contraseña con al menos una mayúscula, una minúscula y un número
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,}$/;
  if (!passwordRegex.test(password)) {
    errors.push({ message: "La contraseña debe contener al menos una mayúscula, una minúscula y un número" });
  }

  if (password !== password2) {
    errors.push({ message: "Las contraseñas no coinciden" });
  }

  if (errors.length > 0) {
    res.render("register", { errors, name, lastname, document_type, id_number, email, program, password, password2 });
  } else {
    hashedPassword = await bcrypt.hash(password, 10);
    // Validación superada
    pool.query(
      `SELECT * FROM users
        WHERE email = $1`,
      [email],
      (err, results) => {
        if (err) {
          console.log(err);
        }

        if (results.rows.length > 0) {
          return res.render("register", {
            message: "El correo electrónico ya está registrado"
          });
        } else {
          pool.query(
            `INSERT INTO users (name, lastname, document_type, id_number, email, program, password, active)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING id, password`,
            [name, lastname, document_type, id_number, email, program, hashedPassword, true], // Asegúrate de establecer active en true
            (err, results) => {
              if (err) {
                throw err;
              }
              req.flash("success_msg", "Te has registrado correctamente, inicia sesión");
              res.redirect("/users/login");
            }
          );
        }
      }
    );
  }
});

// Actualizar user
app.post("/users/update/:id", async (req, res) => {
  const userId = req.params.id;
  let name, lastname, document_type, id_number, program, email, password, active;

  // Verifica los campos enviados en la solicitud y actualiza las variables correspondientes
  if (req.body.newPassword) {
    const { name: userName, lastname: userLastname, document_type: userDocumentType, id_number: userIdNumber, program: userProgram, email: userEmail, active } = req.user;
    const { newPassword, oldPassword, confirmPassword } = req.body;

    // Verifica si la nueva contraseña y la confirmación de la contraseña son iguales
    if (newPassword !== confirmPassword) {
      console.log("La nueva contraseña y la confirmación de la contraseña no coinciden");
    }

    name = userName;
    lastname = userLastname;
    document_type = userDocumentType;
    id_number = userIdNumber;
    program = userProgram;
    email = userEmail;
    password = newPassword;

  } else if (req.body.email) {
    const { name: userName, lastname: userLastname, document_type: userDocumentType, id_number: userIdNumber, program: userProgram, password: userPassword, active } = req.user;
    const { email: userEmail } = req.body;
    name = userName;
    lastname = userLastname;
    document_type = userDocumentType;
    id_number = userIdNumber;
    program = userProgram;
    email = userEmail;
    password = userPassword;
  } else {
    const { name: userName, lastname: userLastname, document_type: userDocumentType, id_number: userIdNumber, program: userProgram } = req.body;
    const { password: userPassword, email: userEmail, active } = req.user;
    name = userName;
    lastname = userLastname;
    document_type = userDocumentType;
    id_number = userIdNumber;
    program = userProgram;
    email = userEmail;
    password = userPassword;
  }

  try {
    // Verifica si el usuario existe
    const userExists = await pool.query(
      "SELECT * FROM users WHERE id = $1",
      [userId]
    );

    if (userExists.rows.length === 0) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const userData = userExists.rows[0];

    // Verifica si se proporciona una nueva contraseña
    if (req.body.newPassword) {
      const { oldPassword, newPassword } = req.body;

      // Verifica si la contraseña anterior coincide con la almacenada en la base de datos
      const passwordMatch = await bcrypt.compare(oldPassword, userData.password);

      if (!passwordMatch) {
        // Si la contraseña anterior no coincide, devuelve un mensaje de error
        return res.json({ success: false, message: "La contraseña no coincide" });
      }

      // Si la contraseña anterior coincide, actualiza la contraseña
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      password = hashedPassword; // Actualiza la contraseña con la nueva contraseña hasheada
    }

    // Verifica si la cuenta está activa o desactivada
    if (active !== undefined) {
      // Actualiza el campo 'active'
      await pool.query(
        "UPDATE users SET active = $1 WHERE id = $2",
        [active, userId]
      );
    }

    if (req.body.email) {
      const { oldPassword } = req.body;

      // Verifica si la contraseña anterior coincide con la almacenada en la base de datos
      const passwordMatch = await bcrypt.compare(oldPassword, userData.password);

      if (!passwordMatch) {
        // Si la contraseña anterior no coincide, devuelve un mensaje de error
        return res.json({ success: false, message: "La contraseña no coincide" });
      }
    }

    // Actualiza los datos del usuario
    await pool.query(
      "UPDATE users SET name = $1, lastname = $2, document_type = $3, id_number = $4, email = $5, program = $6, password = $7 WHERE id = $8",
      [name, lastname, document_type, id_number, email, program, password, userId]
    );
    res.redirect("/users/profile");
  } catch (error) {
    console.error("Error al actualizar el usuario:", error);
    res.status(500).json({ error: "Error al actualizar el usuario" });
  }
});

app.post("/users/deactivate/:id", async (req, res) => {
  const userId = req.params.id;

  try {
    // Actualiza el valor 'active' a false en la base de datos
    await pool.query(
      "UPDATE users SET active = false WHERE id = $1",
      [userId]
    );

    req.flash("success_msg", "Tu cuenta ha sido desactivada exitosamente");
    res.redirect("/users/login"); // Redirecciona a la página de inicio de sesión u otra página
  } catch (error) {
    console.error("Error al desactivar la cuenta:", error);
    res.status(500).json({ error: "Error al desactivar la cuenta" });
  }
});


app.get("/dashboard/publicar", async (req, res) => {
  res.render("dashboard.ejs", { user: req.user }); // Renderiza el formulario de publicación en el dashboard
});

// Dentro del endpoint de publicación de solicitudes
app.post("/dashboard/publicar", (req, res) => {
  const { tipo, materia, tema, fecha, hora } = req.body; // Añadir hora aquí
  const usuario_id = req.user.id;

  // Construir el objeto JSON con los datos del usuario
  const userData = {
    id: req.user.id,
    name: req.user.name,
    lastname: req.user.lastname,
    email: req.user.email,
    document_type: req.user.document_type,
    id_number: req.user.id_number,
    program: req.user.program,
    // Agrega más datos del usuario si es necesario
  };

  // Insertar la nueva solicitud en la base de datos
  pool.query(
    `INSERT INTO solicitudes (user_data, tipo_servicio, materia, tema_interes, fecha_reunion, hora)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING solicitud_id`,
    [userData, tipo, materia, tema, fecha, hora], // Añadir hora aquí
    (err, results) => {
      if (err) {
        console.error("Error al insertar solicitud:", err);
        req.flash("error_msg", "Error al crear la solicitud");
        return res.redirect("/dashboard/publicar");
      }

      req.flash("success_msg", "Solicitud creada exitosamente");
      res.redirect("/users/dashboard");
    }
  );
});


// Eliminar una publicación por su ID
app.delete('/api/eliminar-publicacion/:id', async (req, res) => {
  try {
    const publicacionId = req.params.id;

    // Realizar la consulta para eliminar la publicación por su ID
    const result = await pool.query(
      'DELETE FROM solicitudes WHERE solicitud_id = $1',
      [publicacionId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'La publicación no se encontró o ya ha sido eliminada' });
    }

    res.json({ message: 'Publicación eliminada correctamente' });
  } catch (error) {
    console.error('Error al eliminar la publicación:', error);
    res.status(500).json({ error: 'Error al eliminar la publicación' });
  }
});


//Publicaciones por id de usuario
app.get("/api/publicaciones-usuario/:id", async (req, res) => {
  const userId = req.params.id; // Obtener el id de la URL
  try {
    const solicitudesData = await pool.query(
      "SELECT * FROM solicitudes WHERE user_data ->> 'id' = $1;",
      [userId] // Pasar el id como parámetro
    );
    // Enviamos las últimas solicitudes como respuesta en formato JSON
    res.json(solicitudesData.rows);
  } catch (error) {
    console.error("Error al obtener las últimas solicitudes:", error);
    res.status(500).json({ error: "Error al obtener las últimas solicitudes" });
  }
});


app.post('/api/publicacion/:id', async (req, res) => {
  try {
    const publicacionId = req.params.id;
    const { tipo, materia, tema, fecha } = req.body;
    // Obtén los datos del usuario de la solicitud
    const userData = req.body.user_data;

    // Realiza la actualización en la base de datos, incluyendo los datos del usuario
    const result = await pool.query(
      "UPDATE solicitudes SET tipo_servicio = $1, materia = $2, tema_interes = $3, fecha_reunion = $4, user_data = $5 WHERE solicitud_id = $6",
      [tipo, materia, tema, fecha, userData, publicacionId]
    );

    res.redirect("/users/profile");
  } catch (error) {
    console.error("Error al actualizar la publicación:", error);
    res.status(500).json({ error: "Error al actualizar la publicación" });
  }
});




app.get("/api/publicacion/:id", async (req, res) => {
  try {
    const publicacionId = req.params.id;
    const solicitudesData = await pool.query(
      "SELECT * FROM solicitudes WHERE solicitud_id = $1;",
      [publicacionId]
    );
    // Enviamos las últimas solicitudes como respuesta en formato JSON
    res.json(solicitudesData.rows);
  } catch (error) {
    console.error("Error al obtener la solicitud:", error);
    res.status(500).json({ error: "Error al obtener la solicitud" });
  }
});




app.get("/api/ultimas-publicaciones", async (req, res) => {
  try {
    const solicitudesData = await pool.query(
      "SELECT * FROM solicitudes ORDER BY fecha_solicitud DESC LIMIT 7;"
    );
    // Enviamos las últimas solicitudes como respuesta en formato JSON
    res.json(solicitudesData.rows);
  } catch (error) {
    console.error("Error al obtener las últimas solicitudes:", error);
    res.status(500).json({ error: "Error al obtener las últimas solicitudes" });
  }
});


app.get("/api/ultimas-solicitudes", async (req, res) => {
  try {
    // Realizamos la consulta para obtener las últimas 5 solicitudes
    const solicitudesData = await pool.query(
      "SELECT * FROM solicitudes WHERE tipo_servicio = 'solicitar' ORDER BY fecha_solicitud DESC LIMIT 10;"
    );

    // Enviamos las solicitudes como respuesta en formato JSON
    res.json(solicitudesData.rows);
  } catch (error) {
    console.error("Error al obtener las últimas solicitudes:", error);
    // En caso de error, enviamos un mensaje de error al cliente
    res.status(500).json({ error: "Error al obtener las últimas solicitudes" });
  }
});


app.get("/api/ultimas-ofrecer", async (req, res) => {
  try {
    // Realizamos la consulta para obtener las últimas 5 solicitudes
    const solicitudesData = await pool.query(
      "SELECT * FROM solicitudes WHERE tipo_servicio = 'ofrecer' ORDER BY fecha_solicitud DESC LIMIT 10;"
    );

    // Enviamos las solicitudes como respuesta en formato JSON
    res.json(solicitudesData.rows);
  } catch (error) {
    console.error("Error al obtener las últimas solicitudes:", error);
    // En caso de error, enviamos un mensaje de error al cliente
    res.status(500).json({ error: "Error al obtener las últimas solicitudes" });
  }
});

app.get("/solicitud/visualizar", async (req, res) => {
  try {
    const solicitudesData = await pool.query(`
      SELECT solicitud_id, tipo_servicio, materia, tema_interes, fecha_reunion, fecha_solicitud, 
             user_data->>'id' AS usuario_id, user_data->>'name' AS usuario_nombre
      FROM solicitudes
      WHERE user_data->>'id' = $1`,
      [req.user.id]
    );
    const solicitudes = solicitudesData.rows;
    res.render("visualizarservicio.ejs", { solicitudes, user: req.user });
  } catch (error) {
    console.error("Error al obtener las solicitudes:", error);
    res.status(500).send("Error al obtener las solicitudes");
  }
});


app.get("/api/search", async (req, res) => {
  const query = req.query.query;
  try {
    const searchResults = await pool.query(`
      SELECT * FROM solicitudes
      WHERE materia ILIKE $1 OR tema_interes ILIKE $1
    `, [`%${query}%`]);

    res.json(searchResults.rows);
  } catch (error) {
    console.error("Error al realizar la búsqueda:", error);
    res.status(500).json({ error: "Error al realizar la búsqueda" });
  }
});


app.post("/users/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.render("login", { errors: [{ message: info.message }] });
    }
    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }
      if (!user.active) {
        return res.render("login", { errors: [{ message: "Tu cuenta está desactivada. Por favor, contacta al administrador." }] });
      }
      return res.redirect("/users/dashboard");
    });
  })(req, res, next);
});

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    // Verificar si la cuenta está activa
    if (req.user.active) {
      return res.redirect("/users/dashboard");
    } else {
      req.flash("error_msg", "Tu cuenta está desactivada. Por favor, contáctanos para obtener ayuda.");
      return res.redirect("/users/login");
    }
  }
  next();
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    // Verificar si la cuenta está activa
    if (req.user.active) {
      return next();
    } else {
      req.flash("error_msg", "Tu cuenta está desactivada. Por favor, contáctanos para obtener ayuda.");
      return res.redirect("/users/login");
    }
  }
  res.redirect("/users/login");
}

app.listen(PORT, () => {
  console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
});


app.get("/api/infouser/:id", async (req, res) => {
  const userId = req.params.id;

  try {
    const userData = await pool.query(
      "SELECT * FROM users WHERE id = $1;",
      [userId]
    );

    if (userData.rows.length === 0) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    res.json(userData.rows[0]);
  } catch (error) {
    console.error("Error al obtener información del usuario:", error);
    res.status(500).json({ error: "Error al obtener información del usuario" });
  }
});

app.get("/api/solicitudById/:id", async (req, res) => {
  const solicitudId = req.params.id;

  try {
    const solicitudData = await pool.query(
        "SELECT s.solicitud_id, s.materia, s.tema_interes, s.fecha_reunion, s.user_data  -> 'id' as idPersona\n" +
        "FROM solicitudes s\n" +
        "JOIN users u ON (s.user_data ->> 'id')::bigint = u.id where s.solicitud_id\t = $1;",
        [solicitudId]
    );
    if (solicitudData.rows.length === 0) {
      return res.status(404).json({message: "Solicitud no encontrada"});
    }
    res.json(solicitudData.rows[0]);
  } catch (error) {
    console.error("Error al obtener la solicitud:", error);
    res.status(500).json({error: "Error al obtener la solicitud"});
  }
});

app.post('/agendar', async (req, res) => {
  const { userName, userEmail, tema, fecha, hora, tutor, pago } = req.body; // Añadir hora aquí

  try {
    const query = `
      INSERT INTO agendas (user_name, user_email, tema, fecha, hora, tutor, pago)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
    `;
    await pool.query(query, [userName, userEmail, tema, fecha, hora, tutor, pago]); // Añadir hora aquí
    res.status(200).send('Agendado con éxito');
  } catch (error) {
    console.error('Error agendando:', error);
    res.status(500).send('Error al agendar');
  }
});