const bcrypt = require('bcrypt');
const mysql = require("mysql2");

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'test'
});

// Supondo que você já tenha uma conexão com o banco de dados
const username = 'Giordano';
const password = '12345';

bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
        console.error('Erro ao hash a senha:', err);
        return;
    }

    // Insira o usuário no banco de dados
    const query = 'INSERT INTO users (username, password) VALUES (?, ?)';
    connection.execute(query, [username, hashedPassword], (error) => {
        if (error) {
            console.error('Erro ao inserir o usuário:', error);
        } else {
            console.log('Usuário criado com sucesso!');
        }
    });
});
