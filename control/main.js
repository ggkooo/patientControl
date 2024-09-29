const { app, BrowserWindow, ipcMain } = require('electron');
const mysql = require('mysql2');
const bcrypt = require('bcrypt'); // Importa a biblioteca bcrypt

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'test'
});

let mainWindow; // Variável global para a janela
let currentUsername; // Variável para armazenar o nome do usuário logado

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 800,
        height: 600,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false // Necessário para o ipcRenderer funcionar
        }
    });

    mainWindow.loadFile('index.html').then(() => {
        console.log('Janela carregada com sucesso.');
    }).catch(err => {
        console.error('Erro ao carregar a janela:', err);
    });
}

// Evento para validação de login
ipcMain.on('login', (event, { username, password }) => {
    // Verifica se o nome de usuário é fornecido
    if (!username || username.trim() === '') {
        event.reply('login-response', { success: false, message: 'Nome de usuário não pode estar vazio.' });
        return;
    }

    const query = 'SELECT * FROM users WHERE username = ?';

    connection.execute(query, [username], (err, results) => {
        if (err) {
            console.error('Erro ao executar a consulta:', err);
            event.reply('login-response', { success: false });
            return;
        }

        if (results.length > 0) {
            const user = results[0];

            // Verifica a senha usando bcrypt
            bcrypt.compare(password, user.password, (err, isMatch) => {
                if (err) {
                    console.error('Erro ao comparar senhas:', err);
                    event.reply('login-response', { success: false });
                    return;
                }

                if (isMatch) {
                    currentUsername = user.username; // Armazena o nome do usuário logado
                    event.reply('login-response', { success: true });
                    mainWindow.loadFile('dashboard.html');

                    // Envia o nome do usuário para a página da conta após o login
                    mainWindow.webContents.on('did-finish-load', () => {
                        mainWindow.webContents.send('set-username', currentUsername);
                    });
                } else {
                    event.reply('login-response', { success: false, message: 'Senha incorreta.' });
                }
            });
        } else {
            event.reply('login-response', { success: false, message: 'Nome de usuário não encontrado.' });
        }
    });
});

// Evento para alteração de senha
ipcMain.on('change-password', (event, { currentPassword, newPassword }) => {
    const username = currentUsername;

    // Primeiro, verifique se a senha atual está correta
    connection.query('SELECT password FROM users WHERE username = ?', [username], (error, results) => {
        if (error) {
            console.error('Erro ao verificar a senha atual:', error);
            event.reply('change-password-result', { success: false, message: 'Erro ao verificar a senha.' });
            return;
        }

        if (results.length > 0) {
            const hashedPassword = results[0].password;

            // Verifica a senha atual usando bcrypt
            bcrypt.compare(currentPassword, hashedPassword, (err, isMatch) => {
                if (err) {
                    console.error('Erro ao comparar senhas:', err);
                    event.reply('change-password-result', { success: false, message: 'Erro ao verificar a senha.' });
                    return;
                }

                if (isMatch) {
                    // A senha atual está correta, agora hash a nova senha
                    bcrypt.hash(newPassword, 10, (err, newHashedPassword) => {
                        if (err) {
                            console.error('Erro ao hash a nova senha:', err);
                            event.reply('change-password-result', { success: false, message: 'Erro ao alterar a senha.' });
                            return;
                        }

                        // Atualiza a nova senha no banco de dados
                        connection.query('UPDATE users SET password = ? WHERE username = ?', [newHashedPassword, username], (err) => {
                            if (err) {
                                console.error('Erro ao alterar a senha:', err);
                                event.reply('change-password-result', { success: false, message: 'Erro ao alterar a senha.' });
                            } else {
                                event.reply('change-password-result', { success: true });
                            }
                        });
                    });
                } else {
                    // A senha atual está incorreta
                    event.reply('change-password-result', { success: false, message: 'Senha atual incorreta.' });
                }
            });
        } else {
            event.reply('change-password-result', { success: false, message: 'Usuário não encontrado.' });
        }
    });
});

// Evento de logout
ipcMain.on('logout', () => {
    currentUsername = null; // Limpa o nome do usuário logado
    mainWindow.loadFile('index.html'); // Redireciona para a tela de login
});

// Quando o aplicativo estiver pronto
app.whenReady().then(() => {
    createWindow();

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) {
            createWindow();
        }
    });
});

// Fecha o aplicativo quando todas as janelas forem fechadas
app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});