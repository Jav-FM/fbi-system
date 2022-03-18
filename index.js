const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();
const { results } = require('./data/agentes');
require('dotenv').config();

app.use(express.static('public'));

// 1. Crear una ruta que autentique a un agente basado en sus credenciales y genera un token con sus datos.

app.get('/SignIn', (req, res) => {
  const { email, password } = req.query;

  if (
    !results.find((user) => user.email === email && user.password === password)
  ) {
    return res.status(401).json({ msg: 'Usuario o contraseña incorrecta.' });
  }

  const payload = {
    email,
    password,
  };

  const token = jwt.sign(payload, process.env.SECRETWORD, {
    expiresIn: 120,
  });

  // 2. Al autenticar un agente, devolver un HTML que:
  //   ● Muestre el email del agente autorizado.
  //   ● Guarde un token en SessionStorage con un tiempo de expiración de 2 minutos.
  //   ● Disponibiliza un hiperenlace para redirigir al agente a una ruta restringida.

  return res.send(`
  <p>El agente con correo ${email} ha sido autorizado para acceder a la  <a href="/rutarestringida?token=${token}"> Ir a ruta restringida</a> </p>

  <script>
  localStorage.setItem("token", JSON.stringify("${token}"))
  </script>
  `);
});

// 3. Crear una ruta restringida que devuelva un mensaje de Bienvenida con el correo del agente autorizado, en caso contrario devolver un estado HTTP que indique que el usuario no está autorizado y un mensaje que menciona la descripción del error.

const requireAuth = (req, res, next) => {
  const { token } = req.query;
  if (!token) return res.send(`<p>No existe token de autorización.</p>`);
  try {
    jwt.verify(token, process.env.SECRETWORD, (err, decoded) => {
      if (err) {
        return res.send(`<p>Token no válido.</p>`);
      } else {
        req.decoded = decoded;
        next();
      }
    });
  } catch (e) {
    if (e.message === 'jtw expired') {
      return res.send(`<p>Token expirado.</p>`);
    }
    return res.send(`<p>Token no válido.</p>`);
  }
};

app.get('/rutarestringida', requireAuth, (req, res) => {
  const { email } = req.decoded;
  res.send(`<p>Bienvenid@ agente ${email}</p>`);
});

app.listen(3000, () => console.log('Server ON'));
