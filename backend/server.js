const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(cookieParser());


const allowedOrigins = ['http://localhost:3000', 'http://your-other-origin.com'];

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: 'GET, POST, PUT, HEAD, PATCH, DELETE',
    credentials: true, // Allow credentials (cookies, authorization headers, etc.)
    preflightContinue: false,
    optionsSuccessStatus: 204
};


app.use(cors(corsOptions));

app.get('/', (req, res) => {
    res.send('Hello World');
});

const route = require('./routes/userRoute');
app.use('/api', route);

const PORT = 8001;

app.listen(PORT, () => { console.log('Server is running on port 8001...........') });

// const os = require('os');

// function getLocalIPAddress() {
//   const interfaces = os.networkInterfaces();
//   for (const name of Object.keys(interfaces)) {
//     for (const iface of interfaces[name]) {
//       if (iface.family === 'IPv4' && !iface.internal) {
//         return iface.address;
//       }
//     }
//   }
//   return 'localhost';
// }

// app.listen(PORT, () => {
//   const ipAddress = getLocalIPAddress();
//   console.log(`Server is running on http://${ipAddress}:${PORT}`);
// });