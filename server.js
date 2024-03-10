const express = require("express");
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
const path = require('path');
require("dotenv").config();
const app = express();

const PORT = process.env.PORT || 3000;

const initializePassport = require("./passportConfig");

initializePassport(passport);

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
// Parsea los detalles de un formulario
app.use(express.urlencoded({ extended: false }));

app.set("view engine", "ejs");

app.use(
  session({
    // Clave que queremos mantener en secreto y que cifrará toda nuestra información
    secret: process.env.SESSION_SECRET,
    // ¿Deberíamos guardar nuestras variables de sesión si no ha habido cambios? No queremos hacerlo
    resave: false,
    // Guardar un valor vacío si no hay valor, lo cual no queremos hacer
    saveUninitialized: false
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

app.get("/users/register", checkAuthenticated, (req, res) => {
  res.render("register.ejs");
});

app.get("/users/login", checkAuthenticated, (req, res) => {
  // flash establece una variable de mensajes. Passport establece el mensaje de error
  console.log(req.session.flash.error);
  res.render("login.ejs");
});

app.get("/users/dashboard", checkNotAuthenticated, (req, res) => {
  console.log(req.isAuthenticated());
  res.render("dashboard", { user: req.user.name });
});

app.get("/users/logout", (req, res) => {
  req.logout();
  res.render("index", { message: "Has cerrado sesión exitosamente" });
});

app.post("/users/register", async (req, res) => {
  let { name, lastname, document_type, id_number, email, program, password, password2 } = req.body;

  let errors = [];

  console.log({
    name,
    lastname,
    document_type,
    id_number,
    email,
    program,
    password,
    password2
  });

  if (!name || !lastname || !document_type || !id_number || !email || !program || !password || !password2) {
    errors.push({ message: "Por favor completa todos los campos" });
  }

  if (password.length < 6) {
    errors.push({ message: "La contraseña debe tener al menos 6 caracteres" });
  }

  if (password !== password2) {
    errors.push({ message: "Las contraseñas no coinciden" });
  }

  if (errors.length > 0) {
    res.render("register", { errors, name, lastname, document_type, id_number, email, program, password, password2 });
  } else {
    hashedPassword = await bcrypt.hash(password, 10);
    console.log(hashedPassword);
    // Validación superada
    pool.query(
      `SELECT * FROM users
        WHERE email = $1`,
      [email],
      (err, results) => {
        if (err) {
          console.log(err);
        }
        console.log(results.rows);

        if (results.rows.length > 0) {
          return res.render("register", {
            message: "El correo electrónico ya está registrado"
          });
        } else {
          pool.query(
            `INSERT INTO users (name, lastname, document_type, id_number, email, program, password)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                RETURNING id, password`,
            [name, lastname, document_type, id_number, email, program, hashedPassword],
            (err, results) => {
              if (err) {
                throw err;
              }
              console.log(results.rows);
              req.flash("success_msg", "Te has registrado correctamente, inicia sesión");
              res.redirect("/users/login");
            }
          );
        }
      }
    );
  }
});

app.post(
  "/users/login",
  passport.authenticate("local", {
    successRedirect: "/users/dashboard",
    failureRedirect: "/users/login",
    failureFlash: true
  })
);

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect("/users/dashboard");
  }
  next();
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/users/login");
}

app.listen(PORT, () => {
  console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
});
