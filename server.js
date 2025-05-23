// Importación de las dependencias necesarias
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Creación de la aplicación Express
const app = express();

// Middleware para procesar JSON
app.use(express.json());

// Almacenamiento temporal de usuarios (en un caso real, esto sería una base de datos)
const usuarios = [];

// Clave secreta para JWT (en producción, esto debería estar en variables de entorno)
const JWT_SECRET = 'tu_clave_secreta';

// Ruta para registro de usuarios
app.post('/registro', async (req, res) => {
    try {
        const { usuario, password } = req.body;

        // Verificar si el usuario ya existe
        if (usuarios.find(u => u.usuario === usuario)) {
            return res.status(400).json({ mensaje: 'El usuario ya existe' });
        }

        // Encriptar la contraseña
        const salt = await bcrypt.genSalt(10);
        const passwordEncriptada = await bcrypt.hash(password, salt);

        // Guardar el usuario
        usuarios.push({
            usuario,
            password: passwordEncriptada
        });

        res.status(201).json({ mensaje: 'Usuario registrado exitosamente' });
    } catch (error) {
        res.status(500).json({ mensaje: 'Error en el servidor' });
    }
});

// Ruta para inicio de sesión
app.post('/login', async (req, res) => {
    try {
        const { usuario, password } = req.body;

        // Buscar el usuario
        const usuarioEncontrado = usuarios.find(u => u.usuario === usuario);
        if (!usuarioEncontrado) {
            return res.status(400).json({ mensaje: 'Error en la autenticación' });
        }

        // Verificar la contraseña
        const passwordValida = await bcrypt.compare(password, usuarioEncontrado.password);
        if (!passwordValida) {
            return res.status(400).json({ mensaje: 'Error en la autenticación' });
        }

        // Generar token JWT
        const token = jwt.sign(
            { usuario: usuarioEncontrado.usuario },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({
            mensaje: 'Autenticación satisfactoria',
            token
        });
    } catch (error) {
        res.status(500).json({ mensaje: 'Error en el servidor' });
    }
});

// Puerto del servidor
const PORT = process.env.PORT || 3000;

// Iniciar el servidor
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
}); 