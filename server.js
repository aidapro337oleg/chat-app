const express = require('express');
const https = require('https');
const http = require('http');
const socketIo = require('socket.io');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const app = express();

const PORT = process.env.PORT || 3000;

// Try to use HTTPS if certificates exist, otherwise fall back to HTTP
let server;
let isHttps = false;

try {
  if (fs.existsSync('./ssl/cert.pem') && fs.existsSync('./ssl/key.pem')) {
    const cert = fs.readFileSync('./ssl/cert.pem');
    const key = fs.readFileSync('./ssl/key.pem');
    
    if (cert.length > 0 && key.length > 0) {
      const options = {
        cert: cert,
        key: key
      };
      server = https.createServer(options, app);
      isHttps = true;
      console.log('🔐 Using HTTPS');
    } else {
      throw new Error('SSL certificates are empty');
    }
  } else {
    throw new Error('SSL certificates not found');
  }
} catch (error) {
  server = http.createServer(app);
  console.log('🔓 Using HTTP (for development)');
  console.log('⚠️  SSL Error:', error.message);
}

const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));

// Session storage for multi-user support
const sessions = new Map();

// Middleware for session handling
app.use((req, res, next) => {
    const token = req.headers.authorization || req.query.token;
    if (token) {
        const session = sessions.get(token);
        if (session && session.expires > Date.now()) {
            req.user = session.user;
        }
    }
    next();
});

const DATA_DIR = './data';
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');
const FRIEND_REQUESTS_FILE = path.join(DATA_DIR, 'friend_requests.json');
const VOICE_MESSAGES_DIR = path.join(DATA_DIR, 'voice_messages');
const AVATARS_DIR = path.join(DATA_DIR, 'avatars');

// Ensure data directories exist
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}
if (!fs.existsSync(VOICE_MESSAGES_DIR)) {
    fs.mkdirSync(VOICE_MESSAGES_DIR, { recursive: true });
}
if (!fs.existsSync(AVATARS_DIR)) {
    fs.mkdirSync(AVATARS_DIR, { recursive: true });
}

// Initialize files if they don't exist
if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, JSON.stringify([]));
}
if (!fs.existsSync(MESSAGES_FILE)) {
    fs.writeFileSync(MESSAGES_FILE, JSON.stringify({}));
}
if (!fs.existsSync(FRIEND_REQUESTS_FILE)) {
    fs.writeFileSync(FRIEND_REQUESTS_FILE, JSON.stringify([]));
}

// Helper functions
function getUsers() {
    try {
        const data = fs.readFileSync(USERS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Error reading users file:', error);
        return [];
    }
}

function saveUsers(users) {
    try {
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
        return true;
    } catch (error) {
        console.error('Error saving users file:', error);
        return false;
    }
}

function getMessages() {
    try {
        const data = fs.readFileSync(MESSAGES_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Error reading messages file:', error);
        return {};
    }
}

function saveMessages(messages) {
    try {
        fs.writeFileSync(MESSAGES_FILE, JSON.stringify(messages, null, 2));
        return true;
    } catch (error) {
        console.error('Error saving messages file:', error);
        return false;
    }
}

function getFriendRequests() {
    try {
        const data = fs.readFileSync(FRIEND_REQUESTS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Error reading friend requests file:', error);
        return [];
    }
}

function saveFriendRequests(requests) {
    try {
        fs.writeFileSync(FRIEND_REQUESTS_FILE, JSON.stringify(requests, null, 2));
        return true;
    } catch (error) {
        console.error('Error saving friend requests file:', error);
        return false;
    }
}

function findUserByUsername(username) {
    const users = getUsers();
    return users.find(user => user.username.toLowerCase() === username.toLowerCase());
}

function findUserById(id) {
    const users = getUsers();
    return users.find(user => user.id === id);
}

// Active users and calls
const activeUsers = new Map();
const activeCalls = new Map();

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/chat', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'chat.html'));
});

// API Routes
app.post('/api/register', async (req, res) => {
    const { username, password, email } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    
    if (username.length < 3) {
        return res.status(400).json({ error: 'Username must be at least 3 characters' });
    }
    
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    if (findUserByUsername(username)) {
        return res.status(400).json({ error: 'Username already exists' });
    }
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            id: uuidv4(),
            username,
            email: email || '',
            password: hashedPassword,
            friends: [],
            settings: {
                theme: 'light',
                notifications: true,
                audioDevice: 'default',
                videoDevice: 'default',
                audioOutput: 'default',
                avatar: 'default',
                avatarType: 'default'
            },
            createdAt: new Date().toISOString()
        };
        
        const users = getUsers();
        users.push(newUser);
        const saved = saveUsers(users);
        
        if (!saved) {
            return res.status(500).json({ error: 'Failed to save user' });
        }
        
        // Create session for new user
        const token = uuidv4();
        const { password: _, ...userWithoutPassword } = newUser;
        
        sessions.set(token, {
            user: userWithoutPassword,
            expires: Date.now() + 24 * 60 * 60 * 1000 // 24 hours
        });
        
        res.json({ 
            message: 'User created successfully', 
            user: userWithoutPassword,
            token: token
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    
    const user = findUserByUsername(username);
    if (!user) {
        return res.status(400).json({ error: 'User not found' });
    }
    
    try {
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(400).json({ error: 'Invalid password' });
        }
        
        // Create session
        const token = uuidv4();
        const { password: _, ...userWithoutPassword } = user;
        
        sessions.set(token, {
            user: userWithoutPassword,
            expires: Date.now() + 24 * 60 * 60 * 1000 // 24 hours
        });
        
        res.json({ 
            message: 'Login successful', 
            user: userWithoutPassword,
            token: token
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/validate', (req, res) => {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    const session = sessions.get(token);
    if (!session || session.expires < Date.now()) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
    
    // Update session expiry
    session.expires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    sessions.set(token, session);
    
    const { password, ...userWithoutPassword } = session.user;
    res.json({ user: userWithoutPassword });
});

app.post('/api/logout', (req, res) => {
    const token = req.headers.authorization;
    if (token) {
        sessions.delete(token);
    }
    res.json({ message: 'Logged out successfully' });
});

app.get('/api/users', (req, res) => {
    try {
        const users = getUsers().map(user => {
            const { password, ...userWithoutPassword } = user;
            userWithoutPassword.isOnline = activeUsers.has(user.id);
            return userWithoutPassword;
        });
        res.json(users);
    } catch (error) {
        console.error('Error getting users:', error);
        res.status(500).json({ error: 'Failed to get users' });
    }
});

app.get('/api/users/search/:username', (req, res) => {
    const { username } = req.params;
    const currentUserId = req.query.currentUserId;
    
    console.log('Search request for:', username, 'from user:', currentUserId);
    
    if (!username || username.length < 1) {
        return res.status(400).json({ error: 'Username must be at least 1 character' });
    }
    
    try {
        const users = getUsers();
        const searchResults = users
            .filter(user => {
                // Исключаем текущего пользователя и проверяем совпадение username
                const isNotCurrentUser = user.id !== currentUserId;
                const matchesSearch = user.username.toLowerCase().includes(username.toLowerCase());
                return isNotCurrentUser && matchesSearch;
            })
            .map(user => {
                const { password, ...userWithoutPassword } = user;
                userWithoutPassword.isOnline = activeUsers.has(user.id);
                userWithoutPassword.isFriend = user.friends && user.friends.includes(currentUserId);
                return userWithoutPassword;
            });
        
        console.log(`Search for "${username}" found ${searchResults.length} users`);
        res.json(searchResults);
    } catch (error) {
        console.error('Error searching users:', error);
        res.status(500).json({ error: 'Failed to search users' });
    }
});

// Avatar upload API
app.post('/api/upload-avatar', (req, res) => {
    const { imageData, fileName } = req.body;
    const token = req.headers.authorization;
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    const session = sessions.get(token);
    if (!session) {
        return res.status(401).json({ error: 'Invalid token' });
    }
    
    if (!imageData) {
        return res.status(400).json({ error: 'No image data provided' });
    }
    
    try {
        // Extract base64 data
        const base64Data = imageData.split(',')[1] || imageData;
        const imageBuffer = Buffer.from(base64Data, 'base64');
        
        // Generate unique filename
        const avatarFileName = `avatar_${session.user.id}_${Date.now()}.${fileName.split('.').pop() || 'png'}`;
        const avatarFilePath = path.join(AVATARS_DIR, avatarFileName);
        
        // Save avatar file
        fs.writeFileSync(avatarFilePath, imageBuffer);
        
        // Update user settings
        const users = getUsers();
        const userIndex = users.findIndex(u => u.id === session.user.id);
        if (userIndex !== -1) {
            if (!users[userIndex].settings) users[userIndex].settings = {};
            users[userIndex].settings.avatar = avatarFileName;
            users[userIndex].settings.avatarType = 'custom';
            saveUsers(users);
            
            // Update session
            session.user.settings = users[userIndex].settings;
            sessions.set(token, session);
        }
        
        res.json({ 
            message: 'Avatar uploaded successfully',
            avatarUrl: `/api/avatars/${avatarFileName}`
        });
        
    } catch (error) {
        console.error('Error uploading avatar:', error);
        res.status(500).json({ error: 'Failed to upload avatar' });
    }
});

app.get('/api/avatars/:filename', (req, res) => {
    const { filename } = req.params;
    const avatarPath = path.join(AVATARS_DIR, filename);
    
    if (fs.existsSync(avatarPath)) {
        res.sendFile(avatarPath);
    } else {
        res.status(404).json({ error: 'Avatar not found' });
    }
});

// Voice messages API
app.post('/api/upload-voice', (req, res) => {
    const { audioData, fileName, toUserId, fromUserId } = req.body;
    
    if (!audioData || !toUserId || !fromUserId) {
        return res.status(400).json({ error: 'Missing required data' });
    }
    
    try {
        // Extract base64 data
        const base64Data = audioData.split(',')[1] || audioData;
        const audioBuffer = Buffer.from(base64Data, 'base64');
        
        // Generate unique filename
        const voiceId = uuidv4();
        const voiceFileName = `${voiceId}_${fileName || 'voice_message.wav'}`;
        const voiceFilePath = path.join(VOICE_MESSAGES_DIR, voiceFileName);
        
        // Save voice file
        fs.writeFileSync(voiceFilePath, audioBuffer);
        
        // Save message reference
        const messages = getMessages();
        const chatKey = [fromUserId, toUserId].sort().join('_');
        if (!messages[chatKey]) {
            messages[chatKey] = [];
        }
        
        const messageData = {
            id: uuidv4(),
            from: fromUserId,
            to: toUserId,
            type: 'voice',
            content: `/api/voice-messages/${voiceId}`,
            fileName: voiceFileName,
            timestamp: new Date().toISOString()
        };
        
        messages[chatKey].push(messageData);
        saveMessages(messages);
        
        // Notify recipient
        const recipient = activeUsers.get(toUserId);
        if (recipient) {
            io.to(recipient.socketId).emit('private_message', messageData);
        }
        
        // Also notify sender for immediate update
        const sender = activeUsers.get(fromUserId);
        if (sender) {
            io.to(sender.socketId).emit('private_message', messageData);
        }
        
        res.json({ 
            message: 'Voice message sent successfully',
            messageId: messageData.id
        });
        
    } catch (error) {
        console.error('Error saving voice message:', error);
        res.status(500).json({ error: 'Failed to save voice message' });
    }
});

app.get('/api/voice-messages/:voiceId', (req, res) => {
    const { voiceId } = req.params;
    
    try {
        const files = fs.readdirSync(VOICE_MESSAGES_DIR);
        const voiceFile = files.find(file => file.startsWith(voiceId));
        
        if (!voiceFile) {
            return res.status(404).json({ error: 'Voice message not found' });
        }
        
        const voiceFilePath = path.join(VOICE_MESSAGES_DIR, voiceFile);
        
        // Set proper headers for audio
        res.setHeader('Content-Type', 'audio/wav');
        res.setHeader('Content-Disposition', `inline; filename="${voiceFile}"`);
        
        // Stream the file
        const fileStream = fs.createReadStream(voiceFilePath);
        fileStream.pipe(res);
        
    } catch (error) {
        console.error('Error serving voice message:', error);
        res.status(500).json({ error: 'Failed to serve voice message' });
    }
});

// Delete message API
app.delete('/api/messages/:messageId', (req, res) => {
    const { messageId } = req.params;
    const { userId, friendId } = req.body;
    
    if (!userId || !friendId) {
        return res.status(400).json({ error: 'User ID and Friend ID are required' });
    }
    
    try {
        const messages = getMessages();
        const chatKey = [userId, friendId].sort().join('_');
        
        if (messages[chatKey]) {
            const initialLength = messages[chatKey].length;
            messages[chatKey] = messages[chatKey].filter(msg => msg.id !== messageId);
            
            if (messages[chatKey].length < initialLength) {
                saveMessages(messages);
                
                // Notify both users
                const user1 = activeUsers.get(userId);
                const user2 = activeUsers.get(friendId);
                
                if (user1) {
                    io.to(user1.socketId).emit('message_deleted', { messageId });
                }
                if (user2) {
                    io.to(user2.socketId).emit('message_deleted', { messageId });
                }
                
                return res.json({ message: 'Message deleted successfully' });
            }
        }
        
        return res.status(404).json({ error: 'Message not found' });
    } catch (error) {
        console.error('Error deleting message:', error);
        res.status(500).json({ error: 'Failed to delete message' });
    }
});

// Clear chat API
app.delete('/api/messages/clear/:userId/:friendId', (req, res) => {
    const { userId, friendId } = req.params;
    
    try {
        const messages = getMessages();
        const chatKey = [userId, friendId].sort().join('_');
        
        if (messages[chatKey]) {
            delete messages[chatKey];
            saveMessages(messages);
            
            // Notify both users
            const user1 = activeUsers.get(userId);
            const user2 = activeUsers.get(friendId);
            
            if (user1) {
                io.to(user1.socketId).emit('chat_cleared', { friendId });
            }
            if (user2) {
                io.to(user2.socketId).emit('chat_cleared', { friendId: userId });
            }
            
            return res.json({ message: 'Chat cleared successfully' });
        }
        
        return res.status(404).json({ error: 'Chat not found' });
    } catch (error) {
        console.error('Error clearing chat:', error);
        res.status(500).json({ error: 'Failed to clear chat' });
    }
});

// Link preview API
app.get('/api/link-preview', async (req, res) => {
    const { url } = req.query;
    
    if (!url) {
        return res.status(400).json({ error: 'URL is required' });
    }
    
    try {
        // Simple link preview
        const previewData = {
            title: new URL(url).hostname,
            description: `Ссылка на ${new URL(url).hostname}`,
            url: url,
            image: null
        };
        
        res.json(previewData);
    } catch (error) {
        console.error('Error generating link preview:', error);
        res.status(500).json({ error: 'Failed to generate link preview' });
    }
});

// Friend requests system
app.post('/api/friend-requests', (req, res) => {
    const { fromUserId, toUsername } = req.body;
    
    if (!fromUserId || !toUsername) {
        return res.status(400).json({ error: 'fromUserId and toUsername are required' });
    }
    
    const fromUser = findUserById(fromUserId);
    const toUser = findUserByUsername(toUsername);
    
    if (!fromUser || !toUser) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    if (fromUser.id === toUser.id) {
        return res.status(400).json({ error: 'Cannot send friend request to yourself' });
    }
    
    if (fromUser.friends && fromUser.friends.includes(toUser.id)) {
        return res.status(400).json({ error: 'User is already your friend' });
    }
    
    const friendRequests = getFriendRequests();
    
    // Check if request already exists
    const existingRequest = friendRequests.find(req => 
        req.fromUserId === fromUserId && req.toUserId === toUser.id && req.status === 'pending'
    );
    
    if (existingRequest) {
        return res.status(400).json({ error: 'Friend request already sent' });
    }
    
    const newRequest = {
        id: uuidv4(),
        fromUserId,
        toUserId: toUser.id,
        fromUsername: fromUser.username,
        toUsername: toUser.username,
        status: 'pending',
        createdAt: new Date().toISOString()
    };
    
    friendRequests.push(newRequest);
    const saved = saveFriendRequests(friendRequests);
    
    if (!saved) {
        return res.status(500).json({ error: 'Failed to send friend request' });
    }
    
    // Notify the recipient via socket if online
    const recipient = activeUsers.get(toUser.id);
    if (recipient) {
        io.to(recipient.socketId).emit('friend_request_received', newRequest);
    }
    
    res.json({ message: 'Friend request sent successfully', request: newRequest });
});

app.get('/api/friend-requests/:userId', (req, res) => {
    const { userId } = req.params;
    
    const friendRequests = getFriendRequests();
    const userRequests = friendRequests.filter(req => req.toUserId === userId && req.status === 'pending');
    
    res.json(userRequests);
});

app.post('/api/friend-requests/:requestId/accept', (req, res) => {
    const { requestId } = req.params;
    
    const friendRequests = getFriendRequests();
    const request = friendRequests.find(req => req.id === requestId);
    
    if (!request) {
        return res.status(404).json({ error: 'Friend request not found' });
    }
    
    // Add to friends
    const users = getUsers();
    const fromUserIndex = users.findIndex(u => u.id === request.fromUserId);
    const toUserIndex = users.findIndex(u => u.id === request.toUserId);
    
    if (fromUserIndex === -1 || toUserIndex === -1) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    // Initialize friends arrays if they don't exist
    if (!users[fromUserIndex].friends) users[fromUserIndex].friends = [];
    if (!users[toUserIndex].friends) users[toUserIndex].friends = [];
    
    if (!users[fromUserIndex].friends.includes(users[toUserIndex].id)) {
        users[fromUserIndex].friends.push(users[toUserIndex].id);
    }
    
    if (!users[toUserIndex].friends.includes(users[fromUserIndex].id)) {
        users[toUserIndex].friends.push(users[fromUserIndex].id);
    }
    
    // Update request status
    request.status = 'accepted';
    request.respondedAt = new Date().toISOString();
    
    const usersSaved = saveUsers(users);
    const requestsSaved = saveFriendRequests(friendRequests);
    
    if (!usersSaved || !requestsSaved) {
        return res.status(500).json({ error: 'Failed to accept friend request' });
    }
    
    // Update sessions if users are logged in
    for (let [token, session] of sessions.entries()) {
        if (session.user.id === users[fromUserIndex].id) {
            session.user.friends = users[fromUserIndex].friends;
        }
        if (session.user.id === users[toUserIndex].id) {
            session.user.friends = users[toUserIndex].friends;
        }
    }
    
    // Notify both users
    const fromUserOnline = activeUsers.get(users[fromUserIndex].id);
    const toUserOnline = activeUsers.get(users[toUserIndex].id);
    
    if (fromUserOnline) {
        io.to(fromUserOnline.socketId).emit('friend_request_accepted', {
            requestId: request.id,
            friend: { 
                id: users[toUserIndex].id, 
                username: users[toUserIndex].username,
                settings: users[toUserIndex].settings 
            }
        });
    }
    
    if (toUserOnline) {
        io.to(toUserOnline.socketId).emit('friend_request_accepted', {
            requestId: request.id,
            friend: { 
                id: users[fromUserIndex].id, 
                username: users[fromUserIndex].username,
                settings: users[fromUserIndex].settings 
            }
        });
    }
    
    res.json({ message: 'Friend request accepted successfully' });
});

app.post('/api/friend-requests/:requestId/decline', (req, res) => {
    const { requestId } = req.params;
    
    const friendRequests = getFriendRequests();
    const request = friendRequests.find(req => req.id === requestId);
    
    if (!request) {
        return res.status(404).json({ error: 'Friend request not found' });
    }
    
    // Update request status
    request.status = 'declined';
    request.respondedAt = new Date().toISOString();
    
    const saved = saveFriendRequests(friendRequests);
    
    if (!saved) {
        return res.status(500).json({ error: 'Failed to decline friend request' });
    }
    
    res.json({ message: 'Friend request declined successfully' });
});

app.post('/api/users/:id/friends', (req, res) => {
    const { id } = req.params;
    const { friendUsername } = req.body;
    
    if (!friendUsername) {
        return res.status(400).json({ error: 'friendUsername is required' });
    }
    
    const users = getUsers();
    const user = users.find(u => u.id === id);
    const friend = findUserByUsername(friendUsername);
    
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    if (!friend) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    if (user.id === friend.id) {
        return res.status(400).json({ error: 'Cannot add yourself as friend' });
    }
    
    if (user.friends && user.friends.includes(friend.id)) {
        return res.status(400).json({ error: 'User is already your friend' });
    }
    
    // Initialize friends array if it doesn't exist
    if (!user.friends) user.friends = [];
    if (!friend.friends) friend.friends = [];
    
    // Add to user's friends
    user.friends.push(friend.id);
    
    // Add to friend's friends (mutual friendship)
    if (!friend.friends.includes(user.id)) {
        friend.friends.push(user.id);
    }
    
    const saved = saveUsers(users);
    if (!saved) {
        return res.status(500).json({ error: 'Failed to save friends' });
    }
    
    res.json({ message: 'Friend added successfully' });
});

app.delete('/api/users/:id/friends/:friendId', (req, res) => {
    const { id, friendId } = req.params;
    
    const users = getUsers();
    const user = users.find(u => u.id === id);
    const friend = users.find(u => u.id === friendId);
    
    if (!user || !friend) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    // Remove from user's friends
    if (user.friends) {
        user.friends = user.friends.filter(fid => fid !== friendId);
    }
    
    // Remove from friend's friends
    if (friend.friends) {
        friend.friends = friend.friends.filter(fid => fid !== id);
    }
    
    const saved = saveUsers(users);
    if (!saved) {
        return res.status(500).json({ error: 'Failed to remove friend' });
    }
    
    res.json({ message: 'Friend removed successfully' });
});

app.post('/api/users/:id/settings', (req, res) => {
    const { id } = req.params;
    const { settings } = req.body;
    
    const users = getUsers();
    const userIndex = users.findIndex(u => u.id === id);
    
    if (userIndex === -1) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    // Update user settings
    users[userIndex].settings = { ...users[userIndex].settings, ...settings };
    
    const saved = saveUsers(users);
    if (!saved) {
        return res.status(500).json({ error: 'Failed to save settings' });
    }
    
    // Update session if user is logged in
    for (let [token, session] of sessions.entries()) {
        if (session.user.id === id) {
            session.user.settings = users[userIndex].settings;
            sessions.set(token, session);
        }
    }
    
    res.json({ message: 'Settings updated successfully' });
});

app.get('/api/messages/:userId/:friendId', (req, res) => {
    const { userId, friendId } = req.params;
    
    try {
        const messages = getMessages();
        const chatKey = [userId, friendId].sort().join('_');
        
        const chatMessages = messages[chatKey] || [];
        
        // Sort messages by timestamp
        chatMessages.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
        
        res.json(chatMessages);
    } catch (error) {
        console.error('Error getting messages:', error);
        res.status(500).json({ error: 'Failed to get messages' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Something went wrong!' });
});

// Socket.io connection handling
io.on('connection', (socket) => {
    console.log('User connected:', socket.id);
    
    socket.on('user_online', (userData) => {
        if (!userData || !userData.id) {
            console.log('Invalid user data:', userData);
            return;
        }
        
        activeUsers.set(userData.id, {
            socketId: socket.id,
            user: userData,
            lastSeen: new Date()
        });
        
        console.log(`User ${userData.username} is now online`);
        
        // Notify all users about online status
        io.emit('user_status_changed', {
            userId: userData.id,
            isOnline: true,
            username: userData.username
        });
        
        // Send online users list
        const onlineUsersList = Array.from(activeUsers.values()).map(u => ({
            id: u.user.id,
            username: u.user.username,
            settings: u.user.settings,
            isOnline: true
        }));
        io.emit('online_users', onlineUsersList);
    });
    
    socket.on('private_message', (data) => {
        if (!data || !data.to || !data.message || !data.from) {
            console.log('Invalid message data:', data);
            return;
        }
        
        console.log('Received private message:', data);
        
        // Save message
        const messages = getMessages();
        const chatKey = [data.from, data.to].sort().join('_');
        if (!messages[chatKey]) {
            messages[chatKey] = [];
        }
        
        const messageData = {
            id: uuidv4(),
            from: data.from,
            to: data.to,
            type: data.type || 'text',
            content: data.message,
            timestamp: new Date().toISOString()
        };
        
        // Add additional data based on message type
        if (data.type === 'file') {
            messageData.fileName = data.fileName;
            messageData.fileSize = data.fileSize;
        }
        if (data.type === 'gif') {
            messageData.type = 'gif';
        }
        if (data.urls) {
            messageData.urls = data.urls;
        }
        
        messages[chatKey].push(messageData);
        saveMessages(messages);
        
        console.log(`Message saved to ${chatKey}:`, messageData);
        
        const recipient = activeUsers.get(data.to);
        const sender = activeUsers.get(data.from);
        
        if (recipient) {
            io.to(recipient.socketId).emit('private_message', messageData);
            console.log(`Message sent to recipient ${data.to}`);
        }
        
        if (sender) {
            io.to(sender.socketId).emit('private_message', messageData);
            console.log(`Message sent to sender ${data.from}`);
        }
    });
    
    socket.on('delete_message', (data) => {
        if (!data || !data.messageId || !data.from || !data.to) {
            console.log('Invalid delete message data:', data);
            return;
        }
        
        const messages = getMessages();
        const chatKey = [data.from, data.to].sort().join('_');
        
        if (messages[chatKey]) {
            const initialLength = messages[chatKey].length;
            messages[chatKey] = messages[chatKey].filter(msg => msg.id !== data.messageId);
            
            if (messages[chatKey].length < initialLength) {
                saveMessages(messages);
                
                // Notify both users
                const user1 = activeUsers.get(data.from);
                const user2 = activeUsers.get(data.to);
                
                if (user1) {
                    io.to(user1.socketId).emit('message_deleted', { messageId: data.messageId });
                }
                if (user2) {
                    io.to(user2.socketId).emit('message_deleted', { messageId: data.messageId });
                }
                
                console.log(`Message ${data.messageId} deleted by ${data.from}`);
            }
        }
    });
    
    socket.on('call_user', (data) => {
        if (!data || !data.to || !data.from || !data.offer) {
            console.log('Invalid call data:', data);
            return;
        }
        
        const recipient = activeUsers.get(data.to);
        
        if (recipient) {
            const callId = uuidv4();
            activeCalls.set(callId, {
                from: data.from,
                to: data.to,
                offer: data.offer
            });
            
            io.to(recipient.socketId).emit('incoming_call', {
                from: data.from,
                offer: data.offer,
                callId: callId
            });
            console.log(`Call initiated from ${data.from} to ${data.to}`);
        } else {
            console.log(`Cannot call offline user ${data.to}`);
        }
    });
    
    socket.on('call_accepted', (data) => {
        if (!data || !data.to || !data.answer) {
            console.log('Invalid call acceptance data:', data);
            return;
        }
        
        const caller = activeUsers.get(data.to);
        
        if (caller) {
            io.to(caller.socketId).emit('call_accepted', {
                answer: data.answer
            });
            console.log(`Call accepted by ${data.to}`);
        }
    });
    
    socket.on('call_rejected', (data) => {
        if (!data || !data.to) {
            console.log('Invalid call rejection data:', data);
            return;
        }
        
        const caller = activeUsers.get(data.to);
        
        if (caller) {
            io.to(caller.socketId).emit('call_rejected');
            console.log(`Call rejected by ${data.to}`);
        }
    });
    
    socket.on('end_call', (data) => {
        if (!data || !data.to) {
            console.log('Invalid end call data:', data);
            return;
        }
        
        const otherUser = activeUsers.get(data.to);
        if (otherUser) {
            io.to(otherUser.socketId).emit('call_ended');
        }
    });
    
    socket.on('ice_candidate', (data) => {
        if (!data || !data.to || !data.candidate) {
            console.log('Invalid ICE candidate data:', data);
            return;
        }
        
        const recipient = activeUsers.get(data.to);
        
        if (recipient) {
            io.to(recipient.socketId).emit('ice_candidate', {
                candidate: data.candidate
            });
        }
    });
    
    // Friend request notifications
    socket.on('friend_request_sent', (data) => {
        const recipient = activeUsers.get(data.toUserId);
        if (recipient) {
            io.to(recipient.socketId).emit('friend_request_received', data);
        }
    });
    
    socket.on('disconnect', () => {
        // Find and remove disconnected user
        for (let [userId, userData] of activeUsers.entries()) {
            if (userData.socketId === socket.id) {
                activeUsers.delete(userId);
                
                console.log(`User ${userData.user.username} disconnected`);
                
                // Notify all users about offline status
                io.emit('user_status_changed', {
                    userId: userId,
                    isOnline: false,
                    username: userData.user.username
                });
                
                const onlineUsersList = Array.from(activeUsers.values()).map(u => ({
                    id: u.user.id,
                    username: u.user.username,
                    settings: u.user.settings,
                    isOnline: true
                }));
                io.emit('online_users', onlineUsersList);
                break;
            }
        }
    });
});

// Clean up expired sessions every hour
setInterval(() => {
    const now = Date.now();
    let expiredCount = 0;
    
    for (let [token, session] of sessions.entries()) {
        if (session.expires < now) {
            sessions.delete(token);
            expiredCount++;
        }
    }
    
    if (expiredCount > 0) {
        console.log(`Cleaned up ${expiredCount} expired sessions`);
    }
}, 60 * 60 * 1000); // 1 hour

// Error handlers for the server
process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Start server with error handling
server.listen(PORT, '0.0.0.0', () => {
    console.log(`========================================`);
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📱 Open your Railway URL in browser`);
    if (isHttps) {
        console.log(`🔐 HTTPS Enabled`);
    } else {
        console.log(`⚠️ HTTP Only`);
    }
    console.log(`👥 Multi-user sessions enabled`);
    console.log(`💾 Data directory: ${DATA_DIR}`);
    console.log(`========================================`);
}).on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`❌ Port ${PORT} is already in use on ${HOST}!`);
        console.log('Try one of these solutions:');
        console.log(`1. Close other applications using port ${PORT}`);
        console.log(`2. Use a different port: PORT=3001 node server.js`);
        console.log('3. Wait a few seconds and try again');
    } else if (err.code === 'EACCES') {
        console.error(`❌ Permission denied: Cannot bind to ${HOST}:${PORT}`);
        console.log('Try running as administrator or use a different port');
    } else {
        console.error('❌ Server error:', err.message);
    }
    process.exit(1);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\nShutting down server gracefully...');
    
    // Save all data before exiting
    console.log('Saving user data...');
    const users = getUsers();
    saveUsers(users);
    
    console.log('Saving message data...');
    const messages = getMessages();
    saveMessages(messages);
    
    console.log('Saving friend requests data...');
    const friendRequests = getFriendRequests();
    saveFriendRequests(friendRequests);
    
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});

// Export for testing
module.exports = { app, server, sessions, activeUsers };