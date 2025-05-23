// Importación de las dependencias necesarias
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// Creación de la aplicación Express
const app = express();

// Middleware para procesar JSON
app.use(express.json());

// Almacenamiento temporal de usuarios (en un caso real, esto sería una base de datos)
const usuarios = [];

// Clave secreta para JWT (en producción, esto debería estar en variables de entorno)
const JWT_SECRET = "tu_clave_secreta";

// Middleware para verificar token JWT
const verificarToken = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) {
    return res.status(401).json({ mensaje: "Token no proporcionado" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.usuario = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ mensaje: "Token inválido" });
  }
};

// CREATE - Crear nuevo usuario
app.post("/usuarios", async (req, res) => {
  try {
    const { usuario, password, email, nombre } = req.body;

    // Verificar si el usuario ya existe
    if (usuarios.find((u) => u.usuario === usuario)) {
      return res.status(400).json({ mensaje: "El usuario ya existe" });
    }

    // Encriptar la contraseña
    const salt = await bcrypt.genSalt(10);
    const passwordEncriptada = await bcrypt.hash(password, salt);

    // Crear nuevo usuario
    const nuevoUsuario = {
      id: usuarios.length + 1,
      usuario,
      password: passwordEncriptada,
      email,
      nombre,
      fechaCreacion: new Date(),
    };

    // Guardar el usuario
    usuarios.push(nuevoUsuario);

    res.status(201).json({
      mensaje: "Usuario creado exitosamente",
      usuario: {
        id: nuevoUsuario.id,
        usuario: nuevoUsuario.usuario,
        email: nuevoUsuario.email,
        nombre: nuevoUsuario.nombre,
      },
    });
  } catch (error) {
    res.status(500).json({ mensaje: "Error en el servidor" });
  }
});

// READ - Obtener todos los usuarios
app.get("/usuarios", verificarToken, (req, res) => {
  try {
    // Filtrar información sensible
    const usuariosPublicos = usuarios.map(
      ({ password, ...usuario }) => usuario
    );
    res.json(usuariosPublicos);
  } catch (error) {
    res.status(500).json({ mensaje: "Error en el servidor" });
  }
});

// READ - Obtener un usuario específico
app.get("/usuarios/:id", verificarToken, (req, res) => {
  try {
    const usuario = usuarios.find((u) => u.id === parseInt(req.params.id));
    if (!usuario) {
      return res.status(404).json({ mensaje: "Usuario no encontrado" });
    }
    const { password, ...usuarioPublico } = usuario;
    res.json(usuarioPublico);
  } catch (error) {
    res.status(500).json({ mensaje: "Error en el servidor" });
  }
});

// UPDATE - Actualizar un usuario
app.put("/usuarios/:id", verificarToken, async (req, res) => {
  try {
    const { email, nombre, password } = req.body;
    const usuarioIndex = usuarios.findIndex(
      (u) => u.id === parseInt(req.params.id)
    );

    if (usuarioIndex === -1) {
      return res.status(404).json({ mensaje: "Usuario no encontrado" });
    }

    // Actualizar campos
    if (email) usuarios[usuarioIndex].email = email;
    if (nombre) usuarios[usuarioIndex].nombre = nombre;
    if (password) {
      const salt = await bcrypt.genSalt(10);
      usuarios[usuarioIndex].password = await bcrypt.hash(password, salt);
    }

    const { password: _, ...usuarioActualizado } = usuarios[usuarioIndex];
    res.json({
      mensaje: "Usuario actualizado exitosamente",
      usuario: usuarioActualizado,
    });
  } catch (error) {
    res.status(500).json({ mensaje: "Error en el servidor" });
  }
});

// DELETE - Eliminar un usuario
app.delete("/usuarios/:id", verificarToken, (req, res) => {
  try {
    const usuarioIndex = usuarios.findIndex(
      (u) => u.id === parseInt(req.params.id)
    );

    if (usuarioIndex === -1) {
      return res.status(404).json({ mensaje: "Usuario no encontrado" });
    }

    usuarios.splice(usuarioIndex, 1);
    res.json({ mensaje: "Usuario eliminado exitosamente" });
  } catch (error) {
    res.status(500).json({ mensaje: "Error en el servidor" });
  }
});

// Ruta para inicio de sesión
app.post("/login", async (req, res) => {
  try {
    const { usuario, password } = req.body;

    // Buscar el usuario
    const usuarioEncontrado = usuarios.find((u) => u.usuario === usuario);
    if (!usuarioEncontrado) {
      return res.status(400).json({ mensaje: "Error en la autenticación" });
    }

    // Verificar la contraseña
    const passwordValida = await bcrypt.compare(
      password,
      usuarioEncontrado.password
    );
    if (!passwordValida) {
      return res.status(400).json({ mensaje: "Error en la autenticación" });
    }

    // Generar token JWT
    const token = jwt.sign(
      {
        id: usuarioEncontrado.id,
        usuario: usuarioEncontrado.usuario,
        email: usuarioEncontrado.email,
      },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      mensaje: "Autenticación satisfactoria",
      token,
      usuario: {
        id: usuarioEncontrado.id,
        usuario: usuarioEncontrado.usuario,
        email: usuarioEncontrado.email,
        nombre: usuarioEncontrado.nombre,
      },
    });
  } catch (error) {
    res.status(500).json({ mensaje: "Error en el servidor" });
  }
});

// Puerto del servidor
const PORT = process.env.PORT || 3000;

// Iniciar el servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
