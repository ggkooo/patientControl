const { app, BrowserWindow, ipcMain } = require('electron');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');

const connection = mysql.createConnection({

    host: 'localhost',
    user: 'root',
    password: '',
    database: 'test'

});

let mainWindow;
let currentUsername;
let currentUserId;

function createWindow() {

    mainWindow = new BrowserWindow({

        width: 800,
        height: 600,
        webPreferences: {

            nodeIntegration: true,
            contextIsolation: false

        }

    });

    mainWindow.loadFile('index.html').then(() => {

        console.log('Janela carregada com sucesso.');

    }).catch(err => {

        console.error('Erro ao carregar a janela:', err);

    });

}


ipcMain.on('login', (event, { username, password }) => {

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

            bcrypt.compare(password, user.password, (err, isMatch) => {

                if (err) {

                    console.error('Erro ao comparar senhas:', err);
                    event.reply('login-response', { success: false });
                    return;

                }

                if (isMatch) {

                    currentUsername = user.username;
                    currentUserId = user.id;

                    event.reply('login-response', { success: true });
                    mainWindow.loadFile('dashboard.html');


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

ipcMain.on('change-password', (event, { currentPassword, newPassword }) => {

    const username = currentUsername;

    connection.query('SELECT password FROM users WHERE username = ?', [username], (error, results) => {

        if (error) {

            console.error('Erro ao verificar a senha atual:', error);
            event.reply('change-password-result', { success: false, message: 'Erro ao verificar a senha.' });
            return;

        }

        if (results.length > 0) {

            const hashedPassword = results[0].password;

            bcrypt.compare(currentPassword, hashedPassword, (err, isMatch) => {

                if (err) {

                    console.error('Erro ao comparar senhas:', err);
                    event.reply('change-password-result', { success: false, message: 'Erro ao verificar a senha.' });
                    return;

                }

                if (isMatch) {

                    bcrypt.hash(newPassword, 10, (err, newHashedPassword) => {

                        if (err) {

                            console.error('Erro ao hash a nova senha:', err);
                            event.reply('change-password-result', { success: false, message: 'Erro ao alterar a senha.' });
                            return;

                        }

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

                    event.reply('change-password-result', { success: false, message: 'Senha atual incorreta.' });

                }

            });

        } else {

            event.reply('change-password-result', { success: false, message: 'Usuário não encontrado.' });

        }

    });

});

ipcMain.on('logout', () => {

    currentUsername = null;
    mainWindow.loadFile('index.html');

});

app.whenReady().then(() => {

    createWindow();

    app.on('activate', () => {

        if (BrowserWindow.getAllWindows().length === 0) {

            createWindow();

        }

    });

});

app.on('window-all-closed', () => {

    if (process.platform !== 'darwin') {

        app.quit();

    }

});