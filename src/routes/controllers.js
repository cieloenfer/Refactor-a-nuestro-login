const bcrypt = require('bcrypt');
const csrf = require('csurf');

// Esta función simula una base de datos de usuarios
const users = [
    {
        id: 1,
        email: 'adminCoder@coder.com',
        passwordHash: '$2b$10$6iYRU4BpIEr1aGv3MNoEa.YkY6z2YMR6ytuNglU2oU9ffNBsMFZ82', // Contraseña: adminCod3r123
        role: 'admin'
    },
    {
        id: 2,
        email: 'usuario@example.com',
        passwordHash: '$2b$10$xazLQnA0iKzZFT3ew6Aab.jvZoBlmCNm2n09qy9mtgZlz2AWgr0E6', // Contraseña: password123
        role: 'usuario'
    }
];

// Controlador de login
async function login(req, res) {
    const { email, password } = req.body;

    // Buscar el usuario por correo electrónico en la base de datos
    const user = users.find(user => user.email === email);

    if (!user) {
        // El usuario no existe
        res.render('login.ejs', { error: 'Credenciales inválidas', csrfToken: req.csrfToken() });
        return;
    }

    // Comparar la contraseña proporcionada con la contraseña almacenada utilizando bcrypt
    const passwordMatch = await bcrypt.compare(password, user.passwordHash);

    if (passwordMatch) {
        // Autenticación exitosa, crear sesión
        req.session.user = {
            id: user.id,
            email: user.email,
            role: user.role
        };
        res.redirect('/products');
    } else {
        // Autenticación fallida
        res.render('login.ejs', { error: 'Credenciales inválidas', csrfToken: req.csrfToken() });
    }
}

module.exports = {
    login
};
