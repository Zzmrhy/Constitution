const express = require('express');
const app = express();
const cors = require('cors');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cron = require('node-cron');
const cookieParser = require('cookie-parser');
const path = require('path');
const ejsMate = require('ejs-mate');
let data = JSON.parse(fs.readFileSync(path.join(__dirname, "rules.json"), 'utf8'));
let violationsData = JSON.parse(fs.readFileSync(path.join(__dirname, "violations.json"), 'utf8'));
let lastResetData = JSON.parse(fs.readFileSync(path.join(__dirname, "lastReset.json"), 'utf8'));
let suggestionsData = JSON.parse(fs.readFileSync(path.join(__dirname, "suggestions.json"), 'utf8'));
let punishmentSuggestionsData = JSON.parse(fs.readFileSync(path.join(__dirname, "punishment_suggestions.json"), 'utf8'));
let pendingApprovalsData = { suggestions: [] };
let rejectedSuggestionsData = { suggestions: [] };
let vetoedSuggestionsData = { suggestions: [] };
let punishmentsData = { punishments: [] };
try {
    pendingApprovalsData = JSON.parse(fs.readFileSync(path.join(__dirname, "pending_approvals.json"), 'utf8'));
} catch (err) {
    console.log('pending_approvals.json not found, initializing empty');
}
try {
    rejectedSuggestionsData = JSON.parse(fs.readFileSync(path.join(__dirname, "rejected_suggestions.json"), 'utf8'));
} catch (err) {
    console.log('rejected_suggestions.json not found, initializing empty');
}
try {
    vetoedSuggestionsData = JSON.parse(fs.readFileSync(path.join(__dirname, "vetoed_suggestions.json"), 'utf8'));
} catch (err) {
    console.log('vetoed_suggestions.json not found, initializing empty');
}
try {
    punishmentsData = JSON.parse(fs.readFileSync(path.join(__dirname, "punishments.json"), 'utf8'));
} catch (err) {
    console.log('punishments.json not found, initializing empty');
}
// Allow CORS with credentials (for cookies). In production, set origin to your frontend URL.
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Serve static files from the public directory (if exists)
app.use(express.static(path.join(__dirname, '../public')));

// Set view engine to EJS
app.engine('ejs', ejsMate);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '../views'));

let rules = data.rules;
let violations = violationsData.violations.map(v => {
  if (typeof v.brokenRules === 'string') {
    v.brokenRules = [v.brokenRules];
  }
  return v;
});
let lastReset = lastResetData.lastReset;
let suggestions = suggestionsData.suggestions || [];
let punishmentSuggestions = punishmentSuggestionsData.suggestions || [];
let pendingApprovals = pendingApprovalsData.suggestions || [];
let rejectedSuggestions = rejectedSuggestionsData.suggestions || [];
let vetoedSuggestions = vetoedSuggestionsData.suggestions || [];
let punishments = punishmentsData.punishments || [];

// Function to clean up old suggestions (older than 24 hours)
function cleanupOldSuggestions() {
    const now = new Date();
    const oneDayMs = 24 * 60 * 60 * 1000;
    suggestions = suggestions.filter(s => {
        const submittedAt = new Date(s.submittedAt);
        return (now - submittedAt) <= oneDayMs;
    });
    saveSuggestions();
}

// Function to clean up old punishment suggestions (older than 24 hours)
function cleanupOldPunishmentSuggestions() {
    const now = new Date();
    const oneDayMs = 24 * 60 * 60 * 1000;
    punishmentSuggestions = punishmentSuggestions.filter(s => {
        const submittedAt = new Date(s.submittedAt);
        return (now - submittedAt) <= oneDayMs;
    });
    savePunishmentSuggestions();
}

// Clean up old suggestions on startup
cleanupOldSuggestions();

function getCurrentPunishment(totalBroken) {
  if (totalBroken === 0) return null;
  for (let p of punishments) {
    if (totalBroken >= p.min && totalBroken <= p.max) {
      return p;
    }
  }
  return null;
}

// Helper for violations history (weekly archives)
function readViolationsHistory() {
    try {
        return JSON.parse(fs.readFileSync('./violations_history.json', 'utf8')) || [];
    } catch (err) {
        return [];
    }
}

function saveViolationsHistory(list) {
    fs.writeFileSync('./violations_history.json', JSON.stringify(list, null, 2));
}

// Function to get the next Monday at 1:00 AM after a given timestamp
function getNextMonday1AM(timestamp) {
    const date = new Date(timestamp);
    const dayOfWeek = date.getDay(); // 0=Sunday, 1=Monday, ..., 6=Saturday
    let daysUntilMonday = (1 - dayOfWeek + 7) % 7;
    if (daysUntilMonday === 0 && date.getHours() < 1) {
        // If it's Monday before 1 AM, next is today at 1 AM
        daysUntilMonday = 0;
    } else if (daysUntilMonday === 0) {
        // If it's Monday after 1 AM, next is next Monday
        daysUntilMonday = 7;
    }
    date.setDate(date.getDate() + daysUntilMonday);
    date.setHours(1, 0, 0, 0);
    return date;
}

// Check if violations need to be reset on startup
const now = new Date();
const nextReset = getNextMonday1AM(lastReset);
if (now >= nextReset) {
    // Archive existing violations before clearing
    try {
        const history = readViolationsHistory();
        history.push({
            archivedAt: now.getTime(),
            periodStart: lastReset || null,
            violations: violations
        });
        saveViolationsHistory(history);
    } catch (err) {
        console.error('Failed to write violations history on startup', err);
    }

    violations = [];
    fs.writeFileSync('./violations.json', JSON.stringify({violations: []}, null, 2));
    lastReset = now.getTime();
    fs.writeFileSync('./lastReset.json', JSON.stringify({lastReset: lastReset}, null, 2));
    console.log('Violations archived and reset on startup at', now.toISOString());
}

// Admin credentials are now read from users.json. Each user object in users.json
// should have the shape: { "admin": true|false, "Email": "...", "Password": "..." }

// Helper to validate an admin using users.json. Reads the file on each call
// (fine for small user lists). Returns user object when valid, otherwise null.
function getUserByEmail(email) {
    try {
        const usersData = JSON.parse(fs.readFileSync('./users.json', 'utf8'));
        return usersData.find(u => u.Email === email) || null;
    } catch (err) {
        return null;
    }
}

function isValidAdmin(email, password) {
    // kept for backward-compat but prefer verifyAdminCredentials which is async
    const user = getUserByEmail(email);
    if (!user) return false;
    return user.Password === password && user.admin === true;
}

// Async password verification that supports bcrypt-hashed passwords.
async function verifyAdminCredentials(email, password) {
    const user = getUserByEmail(email);
    if (!user) return false;
    const stored = user.Password || '';
    const looksHashed = typeof stored === 'string' && stored.startsWith('$2');
    if (looksHashed) {
        try {
            const ok = await bcrypt.compare(password, stored);
            return ok && user.admin === true;
        } catch (err) {
            return false;
        }
    }
    // legacy plaintext
    return stored === password && user.admin === true;
}

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const JWT_EXPIRES = '2h';

function verifyToken(token) {
    try {
        if (!token) return null;
        // token may be 'Bearer <token>'
        if (token.startsWith('Bearer ')) token = token.slice(7);
        const payload = jwt.verify(token, JWT_SECRET);
        return payload;
    } catch (err) {
        return null;
    }
}

function getAccessTokenFromReq(req) {
    // Prefer cookie-based access token
    if (req && req.cookies && req.cookies.accessToken) return req.cookies.accessToken;
    const authHeader = req.headers['authorization'] || req.headers['Authorization'] || '';
    if (authHeader && authHeader.startsWith('Bearer ')) return authHeader.slice(7);
    return null;
}

function verifyAccessTokenFromReq(req) {
    const token = getAccessTokenFromReq(req);
    if (!token) return null;
    return verifyToken(token);
}

// Refresh token storage (simple file-based store)
function readRefreshTokens() {
    try {
        return JSON.parse(fs.readFileSync('./refreshTokens.json', 'utf8')) || [];
    } catch (err) {
        return [];
    }
}

function saveRefreshTokens(list) {
    fs.writeFileSync('./refreshTokens.json', JSON.stringify(list, null, 2));
}

// Read all users (returns array).
function readAllUsers() {
    try {
        return JSON.parse(fs.readFileSync('./users.json', 'utf8')) || [];
    } catch (err) {
        return [];
    }
}

function saveAllUsers(users) {
    fs.writeFileSync('./users.json', JSON.stringify(users, null, 2));
}

function saveSuggestions() {
    fs.writeFileSync('./suggestions.json', JSON.stringify({ suggestions }, null, 2));
}

function savePunishmentSuggestions() {
    fs.writeFileSync('./punishment_suggestions.json', JSON.stringify({ suggestions: punishmentSuggestions }, null, 2));
}

function savePendingApprovals() {
    fs.writeFileSync('./pending_approvals.json', JSON.stringify({ suggestions: pendingApprovals }, null, 2));
}

function saveRejectedSuggestions() {
    fs.writeFileSync('./rejected_suggestions.json', JSON.stringify({ suggestions: rejectedSuggestions }, null, 2));
}

function saveVetoedSuggestions() {
    fs.writeFileSync('./vetoed_suggestions.json', JSON.stringify({ suggestions: vetoedSuggestions }, null, 2));
}

const SALT_ROUNDS = 10;

const PORT = process.env.PORT || 4000;

// Routes for rendering EJS views (moved to top to avoid conflict with API routes)
app.get('/', (req, res) => {
    const payload = verifyAccessTokenFromReq(req);
    const user = payload;
    res.render('layout', { title: 'Home', user });
});

app.get('/rules', (req, res) => {
    const payload = verifyAccessTokenFromReq(req);
    if (!payload) return res.redirect('/');
    const user = payload;
    const isAdmin = payload && payload.admin;
    const totalBroken = violations.reduce((sum, v) => sum + v.brokenRules.length, 0);
    const currentPunishment = getCurrentPunishment(totalBroken);
    res.render('layout', { title: 'Rules', rules, isAdmin, user, totalBroken, currentPunishment });
});

app.get('/violations', (req, res) => {
    const payload = verifyAccessTokenFromReq(req);
    if (!payload) return res.redirect('/');
    const user = payload;
    const isAdmin = payload && payload.admin;
    const isSubAdmin = payload && payload.subAdmin;
    const totalBroken = violations.reduce((sum, v) => sum + v.brokenRules.length, 0);
    const currentPunishment = getCurrentPunishment(totalBroken);
    const editingIndex = req.query.edit ? parseInt(req.query.edit) : null;
    res.render('layout', { title: 'Violations', violations, totalBroken, currentPunishment, user, isAdmin, isSubAdmin, rules, editingIndex });
});

app.get('/punishments', (req, res) => {
    const payload = verifyAccessTokenFromReq(req);
    if (!payload) return res.redirect('/');
    const user = payload;
    const isAdmin = payload && payload.admin;
    const totalBroken = violations.reduce((sum, v) => sum + v.brokenRules.length, 0);
    const currentPunishment = getCurrentPunishment(totalBroken);
    res.render('layout', { title: 'Punishments', punishments, user, isAdmin, totalBroken, currentPunishment });
});

app.get('/violations-history', (req, res) => {
    const payload = verifyAccessTokenFromReq(req);
    if (!payload) return res.redirect('/');
    const user = payload;
    const history = readViolationsHistory();
    res.render('layout', { title: 'Violations History', history, user });
});

app.get('/do', (req, res) => {
    const payload = verifyAccessTokenFromReq(req);
    if (!payload) return res.redirect('/');
    const user = payload;
    res.render('layout', { title: 'What We Do', user });
});

app.get('/suggestions', (req, res) => {
    const payload = verifyAccessTokenFromReq(req);
    if (!payload) return res.redirect('/');
    const user = payload;
    const isAdmin = payload && payload.admin;
    const isSubAdmin = payload && payload.subAdmin;
    const users = readAllUsers();
    // Filter out old suggestions and limit to last 10
    const now = new Date();
    const oneDayMs = 24 * 60 * 60 * 1000;
    const recentSuggestions = suggestions.filter(s => {
        const submittedAt = new Date(s.submittedAt);
        return (now - submittedAt) <= oneDayMs;
    }).slice(-10); // Last 10
    res.render('layout', { title: 'Suggestions', user, isAdmin, isSubAdmin, suggestions: recentSuggestions, users });
});

// API routes for suggestions
app.get('/api/suggestions', (req, res) => {
    res.json({ suggestions });
});

app.post('/api/suggestions', (req, res) => {
    const { suggestion } = req.body;
    const payload = verifyAccessTokenFromReq(req);
    if (!payload) return res.status(401).json({ error: 'Unauthorized' });

    // Only regular users and sub-admins can suggest; admins cannot
    if (payload.admin) return res.status(403).json({ error: 'Admins cannot submit suggestions' });

    if (!suggestion || typeof suggestion !== 'string' || suggestion.trim().length === 0) {
        return res.status(400).json({ error: 'Suggestion text is required' });
    }

    const newSuggestion = {
        id: Date.now().toString(),
        text: suggestion.trim(),
        submittedBy: payload.Email,
        submittedAt: new Date().toISOString(),
        votes: {
            approve: [],
            reject: []
        }
    };

    suggestions.push(newSuggestion);
    saveSuggestions();
    res.status(201).json({ success: true, suggestion: newSuggestion });
});

app.post('/api/suggestions/:id/vote', (req, res) => {
    const { id } = req.params;
    const { vote } = req.body; // 'approve' or 'reject'
    const payload = verifyAccessTokenFromReq(req);
    if (!payload) return res.status(401).json({ error: 'Unauthorized' });

    // Only admins and sub-admins can vote
    if (!payload.admin && !payload.subAdmin) return res.status(403).json({ error: 'Only admins and sub-admins can vote' });

    const suggestion = suggestions.find(s => s.id === id);
    if (!suggestion) return res.status(404).json({ error: 'Suggestion not found' });

    // Sub-admin cannot vote on their own suggestion
    if (payload.subAdmin && suggestion.submittedBy === payload.Email) {
        return res.status(403).json({ error: 'Sub-admins cannot vote on their own suggestions' });
    }

    if (vote !== 'approve' && vote !== 'reject') {
        return res.status(400).json({ error: 'Vote must be approve or reject' });
    }

    // Remove any existing vote by this user
    suggestion.votes.approve = suggestion.votes.approve.filter(email => email !== payload.Email);
    suggestion.votes.reject = suggestion.votes.reject.filter(email => email !== payload.Email);

    // Add the new vote
    suggestion.votes[vote].push(payload.Email);

    // Auto-process based on votes
    const users = readAllUsers();
    let totalEligibleVoters = users.filter(u => u.admin || u.subAdmin).length;
    if (suggestion.submittedBy && users.find(u => u.Email === suggestion.submittedBy && u.subAdmin)) {
        totalEligibleVoters -= 1;
    }
    const approveCount = suggestion.votes.approve.length;
    const rejectCount = suggestion.votes.reject.length;
    const neededForApproval = Math.ceil(totalEligibleVoters / 2) + 1;
    const neededForRejection = Math.ceil(totalEligibleVoters / 2) + 1;

    if (approveCount >= neededForApproval) {
        // Add to rules
        rules.push(suggestion.text);
        fs.writeFileSync('./rules.json', JSON.stringify({ rules }, null, 2));
        // Remove suggestion
        suggestions = suggestions.filter(s => s.id !== id);
    } else if (rejectCount >= neededForRejection) {
        // Add to rejected
        rejectedSuggestions.push({ ...suggestion, rejectedAt: new Date().toISOString(), type: 'rule' });
        // Remove suggestion
        suggestions = suggestions.filter(s => s.id !== id);
    }

    saveSuggestions();
    res.json({ success: true, suggestion });
});

// API routes for punishment suggestions
app.get('/api/punishment-suggestions', (req, res) => {
    res.json({ suggestions: punishmentSuggestions });
});

app.post('/api/punishment-suggestions', (req, res) => {
    const { suggestion } = req.body;
    const payload = verifyAccessTokenFromReq(req);
    if (!payload) return res.status(401).json({ error: 'Unauthorized' });

    // Only regular users and sub-admins can suggest; admins cannot
    if (payload.admin) return res.status(403).json({ error: 'Admins cannot submit suggestions' });

    if (!suggestion || typeof suggestion !== 'string' || suggestion.trim().length === 0) {
        return res.status(400).json({ error: 'Suggestion text is required' });
    }

    const newSuggestion = {
        id: Date.now().toString(),
        text: suggestion.trim(),
        submittedBy: payload.Email,
        submittedAt: new Date().toISOString(),
        votes: {
            approve: [],
            reject: []
        }
    };

    punishmentSuggestions.push(newSuggestion);
    savePunishmentSuggestions();
    res.status(201).json({ success: true, suggestion: newSuggestion });
});

app.post('/api/punishment-suggestions/:id/vote', (req, res) => {
    const { id } = req.params;
    const { vote } = req.body; // 'approve' or 'reject'
    const payload = verifyAccessTokenFromReq(req);
    if (!payload) return res.status(401).json({ error: 'Unauthorized' });

    // Only admins and sub-admins can vote
    if (!payload.admin && !payload.subAdmin) return res.status(403).json({ error: 'Only admins and sub-admins can vote' });

    const suggestion = punishmentSuggestions.find(s => s.id === id);
    if (!suggestion) return res.status(404).json({ error: 'Suggestion not found' });

    // Sub-admin cannot vote on their own suggestion
    if (payload.subAdmin && suggestion.submittedBy === payload.Email) {
        return res.status(403).json({ error: 'Sub-admins cannot vote on their own suggestions' });
    }

    if (vote !== 'approve' && vote !== 'reject') {
        return res.status(400).json({ error: 'Vote must be approve or reject' });
    }

    // Remove any existing vote by this user
    suggestion.votes.approve = suggestion.votes.approve.filter(email => email !== payload.Email);
    suggestion.votes.reject = suggestion.votes.reject.filter(email => email !== payload.Email);

    // Add the new vote
    suggestion.votes[vote].push(payload.Email);

    // Auto-process based on votes
    const users = readAllUsers();
    let totalEligibleVoters = users.filter(u => u.admin || u.subAdmin).length;
    if (suggestion.submittedBy && users.find(u => u.Email === suggestion.submittedBy && u.subAdmin)) {
        totalEligibleVoters -= 1;
    }
    const approveCount = suggestion.votes.approve.length;
    const rejectCount = suggestion.votes.reject.length;
    const neededForApproval = Math.ceil(totalEligibleVoters / 2) + 1;
    const neededForRejection = Math.ceil(totalEligibleVoters / 2) + 1;

    if (approveCount >= neededForApproval) {
        // Add to punishments
        punishments.push({ min: punishments.length * 100 + 1, max: Infinity, punishment: suggestion.text });
        fs.writeFileSync('./punishments.json', JSON.stringify({ punishments }, null, 2));
        // Remove suggestion
        punishmentSuggestions = punishmentSuggestions.filter(s => s.id !== id);
    } else if (rejectCount >= neededForRejection) {
        // Add to rejected
        rejectedSuggestions.push({ ...suggestion, rejectedAt: new Date().toISOString(), type: 'punishment' });
        // Remove suggestion
        punishmentSuggestions = punishmentSuggestions.filter(s => s.id !== id);
    }

    savePunishmentSuggestions();
    res.json({ success: true, suggestion });
});

app.get('/captcha', (req, res) => {
    // Check if user is the target (CMP_BeHedderman@students.ects.org)
    const payload = verifyAccessTokenFromReq(req);
    if (payload && payload.Email === 'CMP_BeHedderman@students.ects.org') {
        res.render('captcha', { title: 'CAPTCHA Verification' });
    } else {
        res.redirect('/');
    }
});

// API routes
app.get('/api/rules', (req, res) => {
    res.json(rules)
});

app.post('/api/rules', (req, res) => {
    const { rule, _method, redirect } = req.body;
    const payload = verifyAccessTokenFromReq(req);
    if (!payload || !payload.admin) return res.status(401).json({ error: 'Unauthorized: Admins only' });

    if (_method === 'DELETE') {
        const index = rules.indexOf(rule);
        if (index !== -1) {
            rules.splice(index, 1);
            fs.writeFileSync('./rules.json', JSON.stringify({rules: rules}, null, 2));
            return res.redirect('/rules');
        } else {
            return res.status(404).json({error: "Rule not found"});
        }
    } else {
        rules.push(rule);
        fs.writeFileSync('./rules.json', JSON.stringify({rules: rules}, null, 2));
        res.redirect(redirect || '/rules');
    }
});

app.post('/api/signin', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        const usersData = readAllUsers();
        const userIndex = usersData.findIndex(u => u.Email === email);
        const user = userIndex !== -1 ? usersData[userIndex] : null;

        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const stored = user.Password || '';
        const looksHashed = typeof stored === 'string' && stored.startsWith('$2');

        if (looksHashed) {
            const match = await bcrypt.compare(password, stored);
            if (!match) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }
        } else {
            // legacy plaintext password - migrate to hashed password
            if (stored !== password) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }
            const hash = await bcrypt.hash(password, SALT_ROUNDS);
            usersData[userIndex].Password = hash;
            saveAllUsers(usersData);
        }

        // create access & refresh tokens and set them as httpOnly cookies
        const currentUser = (usersData && usersData[userIndex]) || user;
        const payload = { Email: currentUser.Email, username: currentUser.username, admin: !!currentUser.admin || !!currentUser.headAdmin, subAdmin: !!currentUser.subAdmin, headAdmin: !!currentUser.headAdmin };
        const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '15m' });
        const refreshToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });

        // persist refresh token
        const refreshList = readRefreshTokens();
        refreshList.push(refreshToken);
        saveRefreshTokens(refreshList);

        // set cookies (httpOnly). For dev on localhost we do not set Secure, but in production set Secure: true
        res.cookie('accessToken', accessToken, { httpOnly: true, sameSite: 'lax', maxAge: 15 * 60 * 1000 });
        res.cookie('refreshToken', refreshToken, { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 });

        console.log(`Signin request: ${req.method} ${req.path} for ${email}`);

        // Special handling for specific email: show captcha modal
        if (email === 'CMP_BeHedderman@students.ects.org') {
            return res.status(200).json({
                success: true,
                message: 'Sign in successful, but captcha required',
                user: payload,
                captchaRequired: true
            });
        }

        return res.status(200).json({
            success: true,
            message: 'Sign in successful',
            user: payload
        });
    } catch (error) {
        console.error('Signin error', error);
        return res.status(500).json({ error: 'Server error reading users' });
    }
});

app.post('/api/signup', async (req, res) => {
    const { email, password, username } = req.body;

    if (!email || !password || !username) {
        return res.status(400).json({ error: 'Email, password, and username are required' });
    }

    try {
        const usersData = readAllUsers();

        // Check if user already exists
        if (usersData.find(u => u.Email === email)) {
            return res.status(409).json({ error: 'User already exists' });
        }

        // Hash the password before storing
        const hash = await bcrypt.hash(password, SALT_ROUNDS);

        // Add new user (non-admin by default)
        const newUser = { admin: false, subAdmin: false, headAdmin: false, username, Email: email, Password: hash };
        usersData.push(newUser);

        // Write updated users to file
        saveAllUsers(usersData);

        // create tokens and set cookies
        const payload = { Email: newUser.Email, username: newUser.username, admin: !!newUser.admin, subAdmin: !!newUser.subAdmin, headAdmin: !!newUser.headAdmin };
        const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '15m' });
        const refreshToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });

        // persist refresh token
        const refreshList = readRefreshTokens();
        refreshList.push(refreshToken);
        saveRefreshTokens(refreshList);

        res.cookie('accessToken', accessToken, { httpOnly: true, sameSite: 'lax', maxAge: 15 * 60 * 1000 });
        res.cookie('refreshToken', refreshToken, { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 });

        return res.status(201).json({
            success: true,
            message: 'User created successfully',
            user: payload
        });
    } catch (error) {
        console.error('Signup error', error);
        return res.status(500).json({ error: 'Server error creating user' });
    }
})

// Endpoint for admins to promote a user to sub-admin role. Requires admin headers.
app.post('/api/promote-subadmin', async (req, res) => {
    // Require a valid access token (cookie or Authorization Bearer) and admin claim
    const payload = verifyAccessTokenFromReq(req);
    if (!payload || !payload.admin) return res.status(401).json({ error: 'Unauthorized: Admins only' });

    const { email: targetEmail } = req.body;
    if (!targetEmail) {
        return res.status(400).json({ error: 'Target email is required' });
    }

    try {
        const usersData = readAllUsers();
        const idx = usersData.findIndex(u => u.Email === targetEmail);
        if (idx === -1) return res.status(404).json({ error: 'User not found' });

        usersData[idx].subAdmin = true;
        saveAllUsers(usersData);
        return res.status(200).json({ success: true, message: 'User promoted to sub-admin' });
    } catch (error) {
        console.error('Promote error', error);
        return res.status(500).json({ error: 'Server error promoting user' });
    }
});

// Demote sub-admin
app.post('/api/demote-subadmin', (req, res) => {
    const payload = verifyAccessTokenFromReq(req);
    if (!payload || !payload.admin) return res.status(401).json({ error: 'Unauthorized: Admins only' });

    const { email: targetEmail } = req.body;
    if (!targetEmail) return res.status(400).json({ error: 'Target email is required' });

    try {
        const usersData = readAllUsers();
        const idx = usersData.findIndex(u => u.Email === targetEmail);
        if (idx === -1) return res.status(404).json({ error: 'User not found' });

        usersData[idx].subAdmin = false;
        saveAllUsers(usersData);
        return res.status(200).json({ success: true, message: 'User demoted from sub-admin' });
    } catch (err) {
        console.error('Demote error', err);
        return res.status(500).json({ error: 'Server error demoting user' });
    }
});

// Admin-only: list users (without passwords)
app.get('/api/users', (req, res) => {
    const payload = verifyAccessTokenFromReq(req);
    if (!payload || !payload.admin) return res.status(401).json({ error: 'Unauthorized: Admins only' });
    const users = readAllUsers().map(u => ({ Email: u.Email, admin: !!u.admin, subAdmin: !!u.subAdmin }));
    res.json({ users });
});

// Return current authenticated user info. Uses accessToken from cookie or Authorization header.
app.get('/api/me', (req, res) => {
    const payload = verifyAccessTokenFromReq(req);
    if (!payload) return res.status(401).json({ error: 'Not authenticated' });
    return res.json({ user: payload });
});

// Refresh endpoint: rotates accessToken using refreshToken cookie.
app.post('/refresh', (req, res) => {
    const refreshToken = req.cookies && req.cookies.refreshToken;
    if (!refreshToken) return res.status(401).json({ error: 'No refresh token' });

    const stored = readRefreshTokens();
    if (!stored.includes(refreshToken)) return res.status(403).json({ error: 'Invalid refresh token' });

    try {
        const payload = jwt.verify(refreshToken, JWT_SECRET);
        // issue new access token
        const accessToken = jwt.sign({ Email: payload.Email, admin: !!payload.admin || !!payload.headAdmin, subAdmin: !!payload.subAdmin, headAdmin: !!payload.headAdmin }, JWT_SECRET, { expiresIn: '15m' });
        res.cookie('accessToken', accessToken, { httpOnly: true, sameSite: 'lax', maxAge: 15 * 60 * 1000 });
        return res.json({ success: true });
    } catch (err) {
        return res.status(403).json({ error: 'Refresh token invalid' });
    }
});

// Signout: remove cookies and revoke refresh token
app.post('/signout', (req, res) => {
    const refreshToken = req.cookies && req.cookies.refreshToken;
    if (refreshToken) {
        let list = readRefreshTokens();
        list = list.filter(t => t !== refreshToken);
        saveRefreshTokens(list);
    }
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    return res.json({ success: true });
});

app.post('/admin-check', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({error: "Email and password are required"});
    }
    const ok = await verifyAdminCredentials(email, password);
    res.json({ isAdmin: ok });
});

app.post('/verify-captcha', (req, res) => {
    // For the absurd captcha, just redirect back or handle as needed
    // Since it's impossible, perhaps always fail or redirect
    res.redirect('/captcha');
});

app.delete('/api/rules', async (req, res) => {
    const ruleToRemove = req.body.rule;
    const payload = verifyAccessTokenFromReq(req);
    if (!payload || !payload.admin) return res.status(401).json({ error: 'Unauthorized: Admins only' });

    const index = rules.indexOf(ruleToRemove);
    if (index !== -1) {
        rules.splice(index, 1);
        fs.writeFileSync('./rules.json', JSON.stringify({rules: rules}, null, 2));
        res.status(200).json({message: "Rule removed successfully"});
    } else {
        res.status(404).json({error: "Rule not found"});
    }
});



// API routes for violations history
app.get('/api/violations-history', (req, res) => {
    try {
        const history = readViolationsHistory();
        return res.json({ history });
    } catch (err) {
        console.error('Failed to read violations history', err);
        return res.status(500).json({ error: 'Failed to read violations history' });
    }
});

app.post('/violations', async (req, res) => {
    const { date, brokenRules } = req.body;
    const payload = verifyAccessTokenFromReq(req);
    if (!payload || !payload.admin) return res.status(401).json({ error: 'Unauthorized: Admins only' });

    let rulesBroken = brokenRules;
    if (typeof rulesBroken === 'string') {
        rulesBroken = [rulesBroken];
    }
    const newViolation = { date, brokenRules: rulesBroken };
    violations.push(newViolation);
    fs.writeFileSync('./violations.json', JSON.stringify({violations: violations}, null, 2));
    res.redirect('/violations');
});

app.put('/violations/:index', async (req, res) => {
    const { index } = req.params;
    const { date, brokenRules } = req.body;
    const payload = verifyAccessTokenFromReq(req);
    if (!payload || !payload.admin) return res.status(401).json({ error: 'Unauthorized: Admins only' });

    if (!date || !brokenRules || !Array.isArray(brokenRules)) {
        return res.status(400).json({ error: 'Date and brokenRules array are required' });
    }
    const idx = parseInt(index);
    if (isNaN(idx) || idx < 0 || idx >= violations.length) {
        return res.status(404).json({ error: 'Violation not found' });
    }
    violations[idx] = { date, brokenRules };
    fs.writeFileSync('./violations.json', JSON.stringify({violations: violations}, null, 2));
    res.json(violations[idx]);
});

app.delete('/violations/:index', async (req, res) => {
    const { index } = req.params;
    const payload = verifyAccessTokenFromReq(req);
    if (!payload || !payload.admin) return res.status(401).json({ error: 'Unauthorized: Admins only' });

    const idx = parseInt(index);
    if (isNaN(idx) || idx < 0 || idx >= violations.length) {
        return res.status(404).json({ error: 'Violation not found' });
    }
    violations.splice(idx, 1);
    fs.writeFileSync('./violations.json', JSON.stringify({violations: violations}, null, 2));
    res.redirect('/violations');
});

// API routes for violations
app.post('/api/violations', async (req, res) => {
    const { violation } = req.body;
    const payload = verifyAccessTokenFromReq(req);
    if (!payload || (!payload.admin && !payload.subAdmin)) return res.status(401).json({ error: 'Unauthorized: Admins or sub-admins only' });

    if (!violation || typeof violation !== 'string' || violation.trim().length === 0) {
        return res.status(400).json({ error: 'Violation text is required' });
    }

    const brokenRules = violation.split(',').map(s => s.trim()).filter(s => s);
    const newViolation = { date: new Date().toISOString(), brokenRules };
    violations.push(newViolation);
    fs.writeFileSync('./violations.json', JSON.stringify({violations: violations}, null, 2));
    res.status(201).json({ success: true });
});

app.delete('/api/violations/:index', async (req, res) => {
    const { index } = req.params;
    const payload = verifyAccessTokenFromReq(req);
    if (!payload || (!payload.admin && !payload.subAdmin)) return res.status(401).json({ error: 'Unauthorized: Admins or sub-admins only' });

    const idx = parseInt(index);
    if (isNaN(idx) || idx < 0 || idx >= violations.length) {
        return res.status(404).json({ error: 'Violation not found' });
    }
    violations.splice(idx, 1);
    fs.writeFileSync('./violations.json', JSON.stringify({violations: violations}, null, 2));
    res.json({ success: true });
});

// Schedule to reset violations every Monday at 1:00 AM
cron.schedule('0 1 * * 1', () => {
    const now = new Date();
    try {
        // Archive current violations before clearing
        const history = readViolationsHistory();
        history.push({
            archivedAt: now.getTime(),
            periodStart: lastReset || null,
            violations: violations
        });
        saveViolationsHistory(history);
    } catch (err) {
        console.error('Failed to write violations history during scheduled reset', err);
    }

    violations = [];
    fs.writeFileSync('./violations.json', JSON.stringify({violations: []}, null, 2));
    lastReset = Date.now();
    fs.writeFileSync('./lastReset.json', JSON.stringify({lastReset: lastReset}, null, 2));
    console.log('Violations archived and reset at', new Date().toISOString());
});

// Schedule to clean up old suggestions every day at 1:00 AM
cron.schedule('0 1 * * *', () => {
    cleanupOldSuggestions();
    cleanupOldPunishmentSuggestions();
    console.log('Old suggestions and punishment suggestions cleaned up at', new Date().toISOString());
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
})
