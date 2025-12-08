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

// Validate lastReset on server start and reset if invalid or in future
(function validateLastReset() {
    const now = Date.now();
    if (!lastReset || typeof lastReset !== 'number' || lastReset > now) {
        // Reset to last Monday 1:00 AM
        lastReset = getNextMonday1AM(now - 7 * 24 * 60 * 60 * 1000).getTime();
        fs.writeFileSync('./lastReset.json', JSON.stringify({ lastReset }, null, 2));
        console.log('lastReset was invalid or in future. Resetting to', new Date(lastReset).toISOString());
    }
})();
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

// Function to clean up old violations history (older than 30 days)
function cleanupOldViolationsHistory() {
    const now = new Date();
    const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;
    let history = readViolationsHistory();
    history = history.filter(entry => {
        const archivedAt = new Date(entry.archivedAt);
        return (now - archivedAt) <= thirtyDaysMs;
    });
    saveViolationsHistory(history);
    console.log('Old violations history cleaned up at', new Date().toISOString());
}

// Clean up old suggestions on startup
cleanupOldSuggestions();

function getCurrentPunishment(totalBroken) {
  if (totalBroken === 0) return null;
  // Sort punishments by min ascending
  const sortedPunishments = punishments.slice().sort((a, b) => a.min - b.min);
  // Find the punishment with the highest min <= totalBroken
  for (let i = sortedPunishments.length - 1; i >= 0; i--) {
    const p = sortedPunishments[i];
    if (totalBroken >= p.min) {
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
            return ok && (user.admin === true || user.headAdmin === true);
        } catch (err) {
            return false;
        }
    }
    // legacy plaintext
    return stored === password && (user.admin === true || user.headAdmin === true);
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

app.get('/violations', (req, res) => {
    const payload = verifyAccessTokenFromReq(req);
    if (!payload) return res.redirect('/');

    // Reload violations from file to get latest data
    let currentViolations = [];
    try {
        const violationsData = JSON.parse(fs.readFileSync(path.join(__dirname, "violations.json"), 'utf8'));
        currentViolations = violationsData.violations || [];
    } catch (err) {
        console.error("Failed to load violations.json", err);
    }

    const user = payload;
    const isAdmin = payload && payload.admin === true;
    const isHeadAdmin = payload && payload.headAdmin === true;
    const isSubAdmin = payload && payload.subAdmin;
    const totalBroken = currentViolations.reduce((sum, v) => sum + v.brokenRules.length, 0);
    const currentPunishment = getCurrentPunishment(totalBroken);
    const editingIndex = req.query.edit ? parseInt(req.query.edit) : null;

    res.render('layout', { title: 'Violations', violations: currentViolations, totalBroken, currentPunishment, user, isAdmin, isHeadAdmin, isSubAdmin, rules, editingIndex, lastReset });
});

app.get('/punishments', (req, res) => {
    const payload = verifyAccessTokenFromReq(req);
    if (!payload) return res.redirect('/');

    // Reload punishments from file to get latest data
    let currentPunishments = [];
    try {
        const punishmentsData = JSON.parse(fs.readFileSync(path.join(__dirname, "punishments.json"), 'utf8'));
        currentPunishments = punishmentsData.punishments || [];
    } catch (err) {
        console.error("Failed to load punishments.json", err);
    }

    // Map punishments to add id and rename punishment -> text, as expected by the view
    const mappedPunishments = currentPunishments.map((p, idx) => ({
        id: p.id || idx.toString(),
        text: p.punishment || '',
        min: p.min !== undefined ? p.min : 0,
        max: p.max !== undefined ? p.max : null
    }));

    // Sort punishments by min value ascending
    mappedPunishments.sort((a, b) => a.min - b.min);

    const user = payload;
    const isAdmin = payload && payload.admin === true;
    const isHeadAdmin = payload && payload.headAdmin === true;
    const isSubAdmin = payload && payload.subAdmin;
    const totalBroken = violations.reduce((sum, v) => sum + v.brokenRules.length, 0);
    const currentPunishment = getCurrentPunishment(totalBroken);

    res.render('layout', { title: 'Punishments', punishments: mappedPunishments, user, isAdmin, isHeadAdmin, isSubAdmin, totalBroken, currentPunishment });
});

app.get('/rules', (req, res) => {
    const payload = verifyAccessTokenFromReq(req);
    if (!payload) return res.redirect('/');

    // Reload rules from file to get latest data
    let currentRules = [];
    try {
        const rulesData = JSON.parse(fs.readFileSync(path.join(__dirname, "rules.json"), 'utf8'));
        currentRules = rulesData.rules || [];
    } catch (err) {
        console.error("Failed to load rules.json", err);
    }

    const user = payload;
    const isAdmin = payload && payload.admin === true;
    const isHeadAdmin = payload && payload.headAdmin === true;
    const isSubAdmin = payload && payload.subAdmin;
    const totalBroken = violations.reduce((sum, v) => sum + v.brokenRules.length, 0);
    const currentPunishment = getCurrentPunishment(totalBroken);

res.render('layout', { title: 'Rules', rules: currentRules, isAdmin, isHeadAdmin, isSubAdmin, user, totalBroken, currentPunishment });
});

app.get('/violations-history', (req, res) => {
    const payload = verifyAccessTokenFromReq(req);
    if (!payload) return res.redirect('/');

    const user = payload;
    const isSubAdmin = payload && payload.subAdmin;
    const history = readViolationsHistory();
    const isPreviousMonth = req.query.previousMonth === 'true';

    let previousMonthViolations = null;
    let ruleCounts = {};

    if (isPreviousMonth) {
        const now = Date.now();
        const thirtyDaysAgo = now - 30 * 24 * 60 * 60 * 1000;
        previousMonthViolations = [];
        history.forEach(entry => {
            if (entry.archivedAt >= thirtyDaysAgo) {
                previousMonthViolations = previousMonthViolations.concat(entry.violations);
            }
        });
        // Aggregate by rule
        previousMonthViolations.forEach(v => {
            v.brokenRules.forEach(rule => {
                ruleCounts[rule] = (ruleCounts[rule] || 0) + 1;
            });
        });
        res.render('layout', { title: 'Previous Month Violations', history: null, previousMonthViolations, ruleCounts, user, isSubAdmin });
    } else {
        res.render('layout', { title: 'Violations History', history, previousMonthViolations, ruleCounts, user, isSubAdmin });
    }
});

app.get('/head-admin-approvals', (req, res) => {
    const payload = verifyAccessTokenFromReq(req);
    if (!payload || !payload.headAdmin) return res.redirect('/');

    // pending suggestions are those waiting for head admin approval
    // Filter suggestions approved by admin/subadmin but not yet acted by head admin
    // Let's assume pendingApprovals array stores such suggestions
    const pendingSuggestions = pendingApprovals || []; // get from memory, or read file if needed

    // rejectedSuggestions accessible here for display (no veto functionality)
    const rejected = rejectedSuggestions || [];

    const user = payload;
    const isSubAdmin = payload && payload.subAdmin;

    res.render('layout', {
        title: 'Head Admin Approvals',
        user,
        pendingSuggestions,
        rejectedSuggestions: rejected,
        isAdmin: payload.admin === true,
        isHeadAdmin: payload.headAdmin === true,
        isSubAdmin
    });
});

app.get('/suggestions', (req, res) => {
    const payload = verifyAccessTokenFromReq(req);
    if (!payload) return res.redirect('/');

    const user = payload;
    const isAdmin = payload && payload.admin === true;
    const isHeadAdmin = payload && payload.headAdmin === true;
    if (isHeadAdmin) {
        // Hide Suggestions page from headAdmins - redirect or 403
        return res.status(403).send('Access denied');
    }
    const isSubAdmin = payload && payload.subAdmin;

    let users = [];
    try {
        users = readAllUsers();
        if (!Array.isArray(users)) {
            console.error('readAllUsers() did not return an array, defaulting to empty array.');
            users = [];
        }
    } catch (err) {
        console.error('Error reading users in /suggestions route:', err);
        users = [];
    }

    // Filter out old suggestions and limit to last 10
    const now = new Date();
    const oneDayMs = 24 * 60 * 60 * 1000;
    const recentSuggestions = suggestions.filter(s => {
        const submittedAt = new Date(s.submittedAt);
        return (now - submittedAt) <= oneDayMs;
    }).slice(-10); // Last 10
    res.render('layout', { title: 'Suggestions', user, isAdmin, isSubAdmin, isHeadAdmin, suggestions: recentSuggestions, users });
});



app.get('/do', (req, res) => {
    const payload = verifyAccessTokenFromReq(req);
    if (!payload) return res.redirect('/');
    const user = payload;
res.render('layout', { title: 'What We Do', user });
});

app.post('/api/head-admin-approvals/:id', (req, res) => {
    const payload = verifyAccessTokenFromReq(req);
    if (!payload || !payload.headAdmin) return res.status(401).json({ error: 'Unauthorized: Head Admins only' });

    const { id } = req.params;
    const { action } = req.body; // "approve" or "reject"

    if (!id || !action || (action !== 'approve' && action !== 'reject')) {
        return res.status(400).json({ error: 'Invalid request parameters' });
    }

    // Find suggestion in pendingApprovals
    const index = pendingApprovals.findIndex(s => s.id === id);
    if (index === -1) {
        return res.status(404).json({ error: 'Suggestion not found in pending approvals' });
    }
    const suggestion = pendingApprovals[index];

    if (action === 'approve') {
        if (suggestion.type === 'rule') {
            // Add rule
            rules.push(suggestion.text);
            fs.writeFileSync('./rules.json', JSON.stringify({ rules: rules }, null, 2));
        } else if (suggestion.type === 'punishment') {
            // Add punishment
            punishments.push({ id: Date.now().toString(), punishment: suggestion.text, min: suggestion.min, max: suggestion.max });
            fs.writeFileSync('./punishments.json', JSON.stringify({ punishments: punishments }, null, 2));
        }
        // Remove from pending approvals
        pendingApprovals.splice(index, 1);
        savePendingApprovals();
    } else {
        // Move suggestion to rejectedSuggestions (without veto option)
        rejectedSuggestions.push({ ...suggestion, rejectedAt: new Date().toISOString() });
        pendingApprovals.splice(index, 1);
        savePendingApprovals();
        saveRejectedSuggestions();
    }

    return res.json({ success: true, message: `Suggestion ${action}d` });
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

    // Only admins and sub-admins can vote; exclude headAdmins
    if ((!payload.admin && !payload.subAdmin) || payload.headAdmin) return res.status(403).json({ error: 'Only admins and sub-admins can vote (head admins excluded)' });

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
        // Move to pendingApprovals instead of adding to rules
        pendingApprovals.push({
            id: suggestion.id,
            text: suggestion.text,
            submittedBy: suggestion.submittedBy,
            submittedAt: suggestion.submittedAt,
            votes: suggestion.votes,
            type: 'rule'
        });
        // Remove from suggestions
        suggestions = suggestions.filter(s => s.id !== id);
        savePendingApprovals();
    } else if (rejectCount >= neededForRejection) {
        // Add to rejected
        rejectedSuggestions.push({ ...suggestion, rejectedAt: new Date().toISOString(), type: 'rule' });
        // Remove from suggestions
        suggestions = suggestions.filter(s => s.id !== id);
    }

    saveSuggestions();
    saveRejectedSuggestions();
    res.json({ success: true, suggestion });
});

// API routes for punishment suggestions
app.get('/api/punishment-suggestions', (req, res) => {
    res.json({ suggestions: punishmentSuggestions });
});

app.post('/api/punishment-suggestions', (req, res) => {
    const { suggestion, min, max } = req.body;
    const payload = verifyAccessTokenFromReq(req);
    if (!payload) return res.status(401).json({ error: 'Unauthorized' });

    // Only regular users and sub-admins can suggest; admins cannot
    if (payload.admin) return res.status(403).json({ error: 'Admins cannot submit suggestions' });

    if (!suggestion || typeof suggestion !== 'string' || suggestion.trim().length === 0) {
        return res.status(400).json({ error: 'Suggestion text is required' });
    }
    if (typeof min !== 'number' || min < 0) {
        return res.status(400).json({ error: 'Min must be a number >= 0' });
    }
    if (typeof max !== 'number' || max < 0) {
        return res.status(400).json({ error: 'Max must be a number >= 0' });
    }
    if (max < min) {
        return res.status(400).json({ error: 'Max must be >= min' });
    }

    const newSuggestion = {
        id: Date.now().toString(),
        text: suggestion.trim(),
        min: min,
        max: max,
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
        // Move to pendingApprovals instead of immediate action (head admin approval)
        pendingApprovals.push({
            id: suggestion.id,
            text: suggestion.text,
            min: suggestion.min,
            max: suggestion.max,
            submittedBy: suggestion.submittedBy,
            submittedAt: suggestion.submittedAt,
            votes: suggestion.votes,
            type: 'punishment'
        });
        // Remove from punishmentSuggestions
        punishmentSuggestions = punishmentSuggestions.filter(s => s.id !== id);
        savePendingApprovals();
    } else if (rejectCount >= neededForRejection) {
        // Add to rejected
        rejectedSuggestions.push({ ...suggestion, rejectedAt: new Date().toISOString(), type: 'punishment' });
        // Remove suggestion
        punishmentSuggestions = punishmentSuggestions.filter(s => s.id !== id);
    }

    savePunishmentSuggestions();
    saveRejectedSuggestions();
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
    if (!payload || (!(payload.admin || payload.headAdmin))) {
        return res.status(401).json({ error: 'Unauthorized: Admins or Head Admins only' });
    }

    // Reload rules from file to get latest data for consistency
    let currentRules = [];
    try {
        const rulesData = JSON.parse(fs.readFileSync(path.join(__dirname, "rules.json"), 'utf8'));
        currentRules = rulesData.rules || [];
    } catch (err) {
        console.error("Failed to load rules.json", err);
    }

    if (_method === 'DELETE') {
        // Allow both admin and headAdmin to delete rules
        if (!(payload.admin || payload.headAdmin)) {
            return res.status(401).json({ error: 'Unauthorized: Admins or Head Admins only' });
        }
        const index = currentRules.indexOf(rule);
        if (index !== -1) {
            currentRules.splice(index, 1);
            fs.writeFileSync('./rules.json', JSON.stringify({ rules: currentRules }, null, 2));
            return res.redirect('/rules');
        } else {
            return res.status(404).json({ error: "Rule not found" });
        }
    } else {
        // Only admin can add rules, headAdmin cannot add
        if (!payload.admin) {
            return res.status(403).json({ error: 'Forbidden: Head Admins cannot add rules' });
        }
        currentRules.push(rule);
        fs.writeFileSync('./rules.json', JSON.stringify({ rules: currentRules }, null, 2));
        res.redirect(redirect || '/rules');
    }
});

app.post('/api/signin', async (req, res) => {
    const { email, password } = req.body;

    console.log(`[SignIn] Received signin request for email: ${email}`);

    if (!email || !password) {
        console.log(`[SignIn][Error] Missing email or password.`);
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        const usersData = readAllUsers();
        const userIndex = usersData.findIndex(u => u.Email === email);
        const user = userIndex !== -1 ? usersData[userIndex] : null;

        if (!user) {
            console.log(`[SignIn][Error] User not found for email: ${email}`);
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const stored = user.Password || '';
        const looksHashed = typeof stored === 'string' && stored.startsWith('$2');

        if (looksHashed) {
            const match = await bcrypt.compare(password, stored);
            console.log(`[SignIn] Password hash comparison result: ${match}`);
            if (!match) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }
        } else {
            // legacy plaintext password - migrate to hashed password
            if (stored !== password) {
                console.log(`[SignIn][Error] Plaintext password mismatch`);
                return res.status(401).json({ error: 'Invalid email or password' });
            }
            const hash = await bcrypt.hash(password, SALT_ROUNDS);
            usersData[userIndex].Password = hash;
            saveAllUsers(usersData);
            console.log(`[SignIn] Password hash migration performed for user: ${email}`);
        }

        // create access & refresh tokens and set them as httpOnly cookies
        const currentUser = (usersData && usersData[userIndex]) || user;
        const payload = { Email: currentUser.Email, username: currentUser.username, admin: !!currentUser.admin || !!currentUser.headAdmin, subAdmin: !!currentUser.subAdmin, headAdmin: !!currentUser.headAdmin };
        const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
        const refreshToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });

        console.log(`[SignIn] JWT access and refresh tokens created for email: ${email}`);

        // persist refresh token
        const refreshList = readRefreshTokens();
        refreshList.push(refreshToken);
        saveRefreshTokens(refreshList);

        // set cookies (httpOnly). For dev on localhost we do not set Secure, but in production set Secure: true
        res.cookie('accessToken', accessToken, { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 });
        res.cookie('refreshToken', refreshToken, { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 });

        // Special handling for specific email: show captcha modal
        if (email === 'CMP_BeHedderman@students.ects.org') {
            console.log(`[SignIn] Captcha required for email: ${email}`);
            return res.status(200).json({
                success: true,
                message: 'Sign in successful, but captcha required',
                user: payload,
                captchaRequired: true
            });
        }

        console.log(`[SignIn] Signin successful for email: ${email}`);
        return res.status(200).json({
            success: true,
            message: 'Sign in successful',
            user: payload
        });
    } catch (error) {
        console.error('[SignIn][Error] Signin error', error);
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
        const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
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
        const accessToken = jwt.sign({ Email: payload.Email, admin: !!payload.admin || !!payload.headAdmin, subAdmin: !!payload.subAdmin, headAdmin: !!payload.headAdmin }, JWT_SECRET, { expiresIn: '7d' });
        res.cookie('accessToken', accessToken, { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 });
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
    const { text, rules } = req.body;
    const payload = verifyAccessTokenFromReq(req);
    if (!payload || (!payload.admin && !payload.subAdmin)) return res.status(401).json({ error: 'Unauthorized: Admins or sub-admins only' });

    if (!text || typeof text !== 'string' || text.trim().length === 0) {
        return res.status(400).json({ error: 'Violation description is required' });
    }

    if (!rules || typeof rules !== 'string' || rules.trim().length === 0) {
        return res.status(400).json({ error: 'At least one rule must be selected' });
    }

    const brokenRules = rules.split(',').map(s => s.trim()).filter(s => s);
    const newViolation = { date: new Date().toISOString(), text: text.trim(), brokenRules };
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

// New manual cleanup endpoint to archive and clear violations if Monday 1:00 AM passed since last reset
app.post('/api/violations/cleanup', (req, res) => {
    const payload = verifyAccessTokenFromReq(req);
    if (!payload || !(payload.admin || payload.headAdmin)) return res.status(401).json({ error: 'Unauthorized: Admin or Head Admin only' });

    const now = new Date();
    const nextReset = getNextMonday1AM(lastReset);

    if (now < nextReset) {
        return res.status(400).json({ error: 'Cleanup not allowed before Monday 1:00 AM' });
    }

    try {
        const history = readViolationsHistory();
        history.push({
            archivedAt: now.getTime(),
            periodStart: lastReset || null,
            violations: violations
        });
        saveViolationsHistory(history);

        // Clear current violations and update lastReset timestamp
        violations = [];
        fs.writeFileSync('./violations.json', JSON.stringify({violations: []}, null, 2));
        lastReset = now.getTime();
        fs.writeFileSync('./lastReset.json', JSON.stringify({lastReset: lastReset}, null, 2));
    } catch (err) {
        console.error('Failed to perform manual violations cleanup', err);
        return res.status(500).json({ error: 'Failed to perform cleanup' });
    }

    return res.json({ success: true, message: 'Violations archived and reset successfully' });
});

// Schedule to clean up old suggestions every day at 1:00 AM
cron.schedule('0 1 * * *', () => {
    cleanupOldSuggestions();
    cleanupOldPunishmentSuggestions();
    console.log('Old suggestions and punishment suggestions cleaned up at', new Date().toISOString());
});

/*
  New API routes for head admins to manage rules, punishments, and violations.
  These routes require headAdmin permission and provide more powerful management capabilities.
*/

// POST add a new rule
app.post('/api/head-admin/rules', (req, res) => {
    const { rule } = req.body;
    const payload = verifyAccessTokenFromReq(req);
    if (!payload || !payload.headAdmin) return res.status(401).json({ error: 'Unauthorized: Head Admins only' });

    if (!rule || typeof rule !== 'string' || rule.trim().length === 0) {
        return res.status(400).json({ error: 'Rule text is required' });
    }

    if (rules.includes(rule.trim())) {
        return res.status(409).json({ error: 'Rule already exists' });
    }

    rules.push(rule.trim());
    fs.writeFileSync('./rules.json', JSON.stringify({ rules: rules }, null, 2));
    res.status(201).json({ success: true, message: 'Rule added' });
});

// DELETE remove a rule
app.delete('/api/head-admin/rules', (req, res) => {
    const { rule } = req.body;
    const payload = verifyAccessTokenFromReq(req);
    if (!payload || !payload.headAdmin) return res.status(401).json({ error: 'Unauthorized: Head Admins only' });

    const index = rules.indexOf(rule);
    if (index === -1) return res.status(404).json({ error: 'Rule not found' });

    rules.splice(index, 1);
    fs.writeFileSync('./rules.json', JSON.stringify({ rules: rules }, null, 2));
    res.json({ success: true, message: 'Rule removed' });
});

// POST add a new punishment
app.post('/api/head-admin/punishments', (req, res) => {
    const { text, min, max } = req.body;
    const payload = verifyAccessTokenFromReq(req);
    if (!payload || !payload.headAdmin) return res.status(401).json({ error: 'Unauthorized: Head Admins only' });

    if (!text || typeof text !== 'string' || text.trim().length === 0) {
        return res.status(400).json({ error: 'Punishment text is required' });
    }

    if (min !== undefined && typeof min !== 'number') {
        return res.status(400).json({ error: 'min must be a number' });
    }
    if (max !== undefined && typeof max !== 'number' && max !== null) {
        return res.status(400).json({ error: 'max must be a number or null' });
    }

    const newPunishment = {
        id: Date.now().toString(),
        text: text.trim(),
        min: min !== undefined ? min : 0,
        max: max !== undefined ? max : null,
    };
    punishments.push(newPunishment);
    fs.writeFileSync('./punishments.json', JSON.stringify({ punishments: punishments }, null, 2));
    res.status(201).json({ success: true, punishment: newPunishment });
});

// PUT edit punishment by id
app.put('/api/head-admin/punishments/:id', (req, res) => {
    const { id } = req.params;
    const { text, min, max } = req.body;
    const payload = verifyAccessTokenFromReq(req);
    if (!payload || !payload.headAdmin) return res.status(401).json({ error: 'Unauthorized: Head Admins only' });

    const index = punishments.findIndex(p => p.id === id);
    if (index === -1) return res.status(404).json({ error: 'Punishment not found' });

    if (text && (typeof text !== 'string' || text.trim().length === 0)) {
        return res.status(400).json({ error: 'Punishment text is required if provided' });
    }
    if (min !== undefined && typeof min !== 'number') {
        return res.status(400).json({ error: 'min must be a number' });
    }
    if (max !== undefined && typeof max !== 'number' && max !== null) {
        return res.status(400).json({ error: 'max must be a number or null' });
    }

    if (text) punishments[index].punishment = text.trim();
    if (min !== undefined) punishments[index].min = min;
    if (max !== undefined) punishments[index].max = max;

    fs.writeFileSync(path.join(__dirname, 'punishments.json'), JSON.stringify({ punishments: punishments }, null, 2));
    res.json({ success: true, punishment: punishments[index] });
});

// DELETE remove punishment by id
app.delete('/api/head-admin/punishments/:id', (req, res) => {
    const { id } = req.params;
    const payload = verifyAccessTokenFromReq(req);
    if (!payload || !payload.headAdmin) return res.status(401).json({ error: 'Unauthorized: Head Admins only' });

    const index = punishments.findIndex(p => p.id === id);
    if (index === -1) return res.status(404).json({ error: 'Punishment not found' });

    punishments.splice(index, 1);
    fs.writeFileSync(path.join(__dirname, 'punishments.json'), JSON.stringify({ punishments: punishments }, null, 2));
    res.json({ success: true, message: 'Punishment removed' });
});

// DELETE remove violation by index
app.delete('/api/head-admin/violations/:index', (req, res) => {
    const { index } = req.params;
    const payload = verifyAccessTokenFromReq(req);
    if (!payload || !payload.headAdmin) return res.status(401).json({ error: 'Unauthorized: Head Admins only' });

    const idx = parseInt(index);
    if (isNaN(idx) || idx < 0 || idx >= violations.length) {
        return res.status(404).json({ error: 'Violation not found' });
    }

    violations.splice(idx, 1);
    fs.writeFileSync('./violations.json', JSON.stringify({ violations: violations }, null, 2));
    res.json({ success: true, message: 'Violation removed' });
});

app.get('/api/lastReset', (req, res) => {
    res.json({ lastReset });
});

app.get('/api/server-time', (req, res) => {
    res.json({ serverTime: new Date().toString() });
});

// Admin endpoint to update lastReset value (for testing purpose)
app.post('/api/admin/update-lastReset', (req, res) => {
    const payload = verifyAccessTokenFromReq(req);
    if (!payload || !(payload.admin || payload.headAdmin)) {
        return res.status(401).json({ error: 'Unauthorized: Admin or Head Admin only' });
    }
    const { lastReset: newLastReset } = req.body;
    if (!newLastReset || typeof newLastReset !== 'number') {
        return res.status(400).json({ error: 'Invalid lastReset timestamp' });
    }

    try {
        lastReset = newLastReset;
        fs.writeFileSync('./lastReset.json', JSON.stringify({ lastReset: lastReset }, null, 2));
        return res.json({ success: true, message: 'lastReset updated' });
    } catch (err) {
        console.error('Failed to update lastReset', err);
        return res.status(500).json({ error: 'Failed to update lastReset' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
})
