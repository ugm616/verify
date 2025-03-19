const express = require('express');
const fs = require('fs').promises;
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Configuration
const CSV_FILE = 'users.enc';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'your-secret-key-should-be-32-chars'; // Use environment variable in production
const ENCRYPTION_IV = process.env.ENCRYPTION_IV || 'your-16char-ivvv'; // 16 characters
const BLOCKED_IPS_FILE = 'blocked_ips.json';

// Email configuration - replace with your email service
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Track failed attempts
const failedAttempts = new Map();

// Load blocked IPs
let blockedIPs = {};
try {
    blockedIPs = JSON.parse(fs.readFileSync(BLOCKED_IPS_FILE, 'utf8'));
} catch (error) {
    console.log('No blocked IPs file found, creating new one');
    fs.writeFileSync(BLOCKED_IPS_FILE, JSON.stringify({}));
}

// CSV functions
async function encryptAndSaveCSV(data) {
    // Convert users array to CSV
    const csvContent = data.map(user => 
        `${user.username},${user.email},${user.identifier},${user.code}`
    ).join('\n');
    
    // Encrypt
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, ENCRYPTION_IV);
    let encrypted = cipher.update(csvContent, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    await fs.writeFile(CSV_FILE, encrypted);
}

async function decryptAndReadCSV() {
    try {
        const encrypted = await fs.readFile(CSV_FILE, 'utf8');
        const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, ENCRYPTION_IV);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        // Parse CSV
        return decrypted.split('\n')
            .filter(line => line.trim())
            .map(line => {
                const [username, email, identifier, code] = line.split(',');
                return { username, email, identifier, code };
            });
    } catch (error) {
        console.error('Error reading users file:', error);
        return [];
    }
}

// Generate random code
function generateRandomCode(length = 12) {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
    let result = '';
    const randomBytes = crypto.randomBytes(length);
    
    for (let i = 0; i < length; i++) {
        result += charset.charAt(randomBytes[i] % charset.length);
    }
    
    return result;
}

// Send email with new code
async function sendNewCodeEmail(email, code) {
    const now = new Date().toISOString();
    
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Your New Verification Code',
        html: `
            <h2>New Verification Code</h2>
            <p>Your account was just verified.</p>
            <p>Your new verification code is: <strong>${code}</strong></p>
            <p>Generated at: ${now}</p>
            <p>This verification was requested from: ${email}</p>
        `
    };
    
    return transporter.sendMail(mailOptions);
}

// Middleware to check if IP is blocked
function checkIPBlocked(req, res, next) {
    const ip = req.ip;
    
    if (blockedIPs[ip] && new Date() < new Date(blockedIPs[ip])) {
        return res.status(403).json({ 
            success: false, 
            message: 'Too many failed attempts. Please try again later.'
        });
    }
    
    next();
}

// Routes
app.post('/api/verify', checkIPBlocked, async (req, res) => {
    const { email, identifier, code } = req.body;
    const ip = req.ip;
    
    // Check if all fields are provided
    if (!email || !identifier || !code) {
        return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    
    try {
        const users = await decryptAndReadCSV();
        
        // Find user with matching identifier
        const user = users.find(u => 
            u.identifier === identifier && u.code === code
        );
        
        if (user) {
            // Reset failed attempts for this IP
            failedAttempts.delete(ip);
            
            // Generate new code
            const newCode = generateRandomCode();
            
            // Update user's code in the CSV
            const updatedUsers = users.map(u => {
                if (u.identifier === identifier) {
                    return { ...u, code: newCode };
                }
                return u;
            });
            
            // Save updated CSV
            await encryptAndSaveCSV(updatedUsers);
            
            // Send email with new code
            await sendNewCodeEmail(user.email, newCode);
            
            return res.json({ success: true });
        } else {
            // Track failed attempts
            const attempts = (failedAttempts.get(ip) || 0) + 1;
            failedAttempts.set(ip, attempts);
            
            // Block IP after 3 failed attempts
            if (attempts >= 3) {
                const blockUntil = new Date();
                blockUntil.setHours(blockUntil.getHours() + 24);
                
                blockedIPs[ip] = blockUntil.toISOString();
                await fs.writeFile(BLOCKED_IPS_FILE, JSON.stringify(blockedIPs));
                
                return res.status(403).json({ 
                    success: false, 
                    message: 'Too many failed attempts. Please try again later.'
                });
            }
            
            return res.json({ success: false, message: 'Unrecognised' });
        }
    } catch (error) {
        console.error('Error verifying user:', error);
        return res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Admin API to add users (would need proper authentication in production)
app.post('/api/admin/add-user', async (req, res) => {
    const { username, email } = req.body;
    
    if (!username || !email) {
        return res.status(400).json({ success: false, message: 'Username and email are required' });
    }
    
    try {
        // Generate identifier (6 digits)
        const identifier = Math.floor(100000 + Math.random() * 900000).toString();
        
        // Generate initial code
        const code = generateRandomCode();
        
        // Read current users
        const users = await decryptAndReadCSV();
        
        // Check if identifier is already in use
        if (users.some(u => u.identifier === identifier)) {
            return res.status(400).json({ success: false, message: 'Please try again (duplicate identifier)' });
        }
        
        // Add new user
        users.push({ username, email, identifier, code });
        
        // Save updated CSV
        await encryptAndSaveCSV(users);
        
        // Send initial code to user
        await sendNewCodeEmail(email, code);
        
        return res.json({ 
            success: true, 
            message: 'User added successfully',
            identifier,
            code
        });
    } catch (error) {
        console.error('Error adding user:', error);
        return res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Serve the main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve the admin page
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// Create initial files if they don't exist
async function init() {
    try {
        await fs.access(CSV_FILE);
    } catch (error) {
        // Create empty encrypted CSV
        await encryptAndSaveCSV([]);
    }
    
    try {
        await fs.access(BLOCKED_IPS_FILE);
    } catch (error) {
        await fs.writeFile(BLOCKED_IPS_FILE, JSON.stringify({}));
    }
}

init();