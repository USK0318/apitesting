const connection = require('./connection');

const userSchema = new connection.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    phone: {
        type: Number,
        required: true
    }
});

const User = connection.model('User', userSchema);

module.exports = User;