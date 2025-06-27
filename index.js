// Src/index.js
const express = require('express');
const fs = require('fs');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const path = require('path');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3001;

// 🔧 Configs
const USERS_FILE = path.join(__dirname, 'users.json');
const dossiersPath = path.join(__dirname, 'data', 'dossiers');
const upload = multer({ dest: path.join(__dirname, 'uploads') });

/////////////////////////////////////////////////////////////////////////////////////////////////////

// 🧱 Middlewares
app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

/////////////////////////////////////////////////////////////////////////////////////////////////////

// 🔍 Logs des requêtes
app.use((req, res, next) => {
  console.log(`➡️  [${req.method}] ${req.originalUrl}`);
  next();
});
/////////////////////////////////////////////////////////////////////////////////////////////////////

// Objet en mémoire pour compter le nombre de tentatives de réponse incorrectes
// à la question secrète par utilisateur (identifié par email).
// Permet de limiter les tentatives (ex: blocage temporaire après 3 essais).
// Note : ce compteur est volatile, il sera remis à zéro au redémarrage du serveur.
const attempts = {};

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////// COTE GENERAL ///////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

// 🔥 Routes

// Route spéciale non numérotée (technique)
app.post('/api/send-pdf', (req, res) => {
  console.log('Reçu un PDF avec une taille:', JSON.stringify(req.body).length, 'octets');
  res.send({ status: 'ok' });
});

/////////////////////////////////////////////////////////////////////////////////////////////////////
// Middleware pour servir les fichiers statiques d’images uploadées
// 🚀 Permet d’accéder aux images via l’URL /uploads/nom_du_fichier
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

/////////////////////////////////////////////////////////////////////////////////////////////////////

// Route n°1
// 👉 Page d’accueil de l’API
app.get('/', (req, res) => {
  res.send('Bienvenue sur l\'API de coaching !');
});

// Route n°2
// 🔐 Route protégée par token
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: `Bienvenue, ${req.user.email}. Ceci est une route protégée.` });
});

/////////////////////////////////////////////////////////////////////////////////////////////////////
// Fonction n°1 

// 🔐 Middleware d’authentification token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  console.log("🧾 [auth] Authorization Header:", authHeader);

  const token = authHeader && authHeader.split(' ')[1];
  console.log("🔐 [auth] Token extrait :", token);

  if (!token) {
    console.log("❌ [auth] Aucun token fourni !");
    return res.sendStatus(401); // Unauthorized
  }

  jwt.verify(token, process.env.JWT_SECRET || 'secret123', (err, user) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        console.log("❌ [auth] Token expiré !");
        return res.status(403).json({ message: 'Token expiré, veuillez vous reconnecter.' });
      }
      console.log("❌ [auth] Erreur vérification token :", err.message);
      return res.sendStatus(403); // Forbidden
    }

    console.log("✅ [auth] Token valide, utilisateur :", user);
    req.user = user;
    next();
  });
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////// CONNEXION GENERAL ///////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 👨‍💼 Route n°3 — Connexion côté coach (et client)

app.post('/login', (req, res) => {
  // 🧾 Extraction des données reçues (email et mot de passe)
  const { email, password } = req.body;

  // 🔐 Connexion spéciale "coach admin" en dur
  if (email === 'coach@admin.com' && password === 'coach123') {
    const token = jwt.sign(
      { email, role: 'coach' },    // Payload avec rôle "coach"
      'secret123',                 // Clé secrète (à sécuriser en prod)
      { expiresIn: '1h' }          // Expiration du token
    );
    return res.json({ message: "Connexion coach réussie", token });
  }

  // 📂 Sinon, lecture du fichier utilisateurs (clients)
  const users = JSON.parse(fs.readFileSync(USERS_FILE));
  const user = users.find(u => u.email === email);

  // ❌ Utilisateur non trouvé
  if (!user) {
    return res.status(400).json({ message: "Utilisateur non trouvé." });
  }

  // 🔑 Vérification du mot de passe
  const passwordMatch = bcrypt.compareSync(password, user.password);
  if (!passwordMatch) {
    return res.status(401).json({ message: "Mot de passe incorrect." });
  }

  // 🆗 Connexion réussie — création d’un token JWT avec rôle "client"
  const token = jwt.sign(
    { email: user.email, role: 'client' },
    'secret123',
    { expiresIn: '1h' }
  );

  // 📤 Envoi de la réponse avec le token
  res.json({ message: "Connexion réussie", token });
});
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////// FIN GENERAL ///////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////


















//////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////// COTE CLIENT ///////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

// 🧍‍♂️ Route POST n°1_Client — Inscription d'un client

app.post('/register', (req, res) => {
  console.log("📥 Requête reçue pour l'inscription d'un nouveau client");

  // 🧾 Extraction des données envoyées dans la requête
  const {
    email, password,
    securityQuestion, securityAnswer,
    profil, mensurationProfil, hygieneVie, objectifs,
    medical, physio, nutrition, activite,
    psychomotivation, preference
  } = req.body;

  // ❌ Vérifie que l'email et le mot de passe sont bien présents
  if (!email || !password) {
    return res.status(400).json({ message: 'Email et mot de passe requis.' });
  }

  // 📂 Lecture du fichier des utilisateurs existants
  let users = [];
  if (fs.existsSync(USERS_FILE)) {
    const data = fs.readFileSync(USERS_FILE);
    users = JSON.parse(data);
  }

  // ❌ Vérifie si l'utilisateur existe déjà
  const userExists = users.find(user => user.email === email);
  if (userExists) {
    return res.status(409).json({ message: 'Utilisateur déjà existant.' });
  }

  // 🔐 Hachage du mot de passe
  const hashedPassword = bcrypt.hashSync(password, 10);

  // 🆕 Création du nouvel utilisateur de base
  const newUser = {
    email,
    password: hashedPassword,
    securityQuestion,
    securityAnswer
  };

  // ➕ Ajout à la liste et sauvegarde dans le fichier users.json
  users.push(newUser);
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));

  // 📁 Création du dossier client individuel
  if (!fs.existsSync(dossiersPath)) {
    fs.mkdirSync(dossiersPath, { recursive: true });
  }

  // 🧼 Nettoyage de l'email pour l'utiliser comme nom de fichier
  const sanitizedEmail = email.replace(/[@.]/g, '_');
  const dossierPath = path.join(dossiersPath, `${sanitizedEmail}.json`);

  // 🗃️ Structure du dossier personnel du client
  const dossier = {
    email,
    profil: profil ? [profil] : [],
    mensurationProfil: mensurationProfil ? [mensurationProfil] : [],
    hygieneVie: hygieneVie ? [hygieneVie] : [],
    objectifs: objectifs ? [objectifs] : [],
    medical: medical ? [medical] : [],
    physio: physio ? [physio] : [],
    nutrition: nutrition ? [nutrition] : [],
    activite: activite ? [activite] : [],
    preference: preference ? [preference] : [],
    mensurations: [],       // 📝 Historique de mensurations à venir
    entrainements: [],      // 🏋️‍♂️ Historique d'entraînements
    performances: [],       // 📊 Suivi de performances
    dietes: []              // 🍽️ Suivi de régimes/dietes
  };

  // 💾 Sauvegarde du dossier client dans un fichier
  console.log("📦 Dossier client enregistré :", dossier);
  fs.writeFileSync(dossierPath, JSON.stringify(dossier, null, 2));

  // ✅ Réponse au client
  res.status(201).json({ message: 'Utilisateur enregistré avec succès.' });
});

////////////////////////////////////////// QUESTION SECRETE ///////////////////////////////////////////////////

// Route POST n°2_Client // Vérifie et retourne la question secrète d’un utilisateur
// 🔍 Reçoit l’email et recherche l’utilisateur dans USERS_FILE
// ⚠️ Vérifie que l’email est fourni et que le fichier utilisateurs existe
// ❌ Renvoie 404 si utilisateur ou question secrète absente
// ✅ Renvoie la question secrète pour l’utilisateur trouvé
app.post('/verify-security-question', (req, res) => {
  console.log('🔥 Requête reçue sur /verify-security-question');

  const { email } = req.body;
  console.log('📩 Email reçu :', email);

  if (!email) {
    console.log('⛔️ Email manquant');
    return res.status(400).json({ message: 'Email requis' });
  }

  let users = [];
  if (fs.existsSync(USERS_FILE)) {
    const fileContent = fs.readFileSync(USERS_FILE, 'utf8');
    users = JSON.parse(fileContent);
    console.log('📚 Utilisateurs chargés :', users.length);
  } else {
    console.log('❌ USERS_FILE introuvable :', USERS_FILE);
  }

  const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  console.log('👤 Utilisateur trouvé :', user ? '✅' : '❌');

  if (!user) {
    return res.status(404).json({ message: 'Aucun utilisateur trouvé avec cet email.' });
  }

  if (!user.security || !user.security.question) {
    console.log('❌ Pas de question secrète définie pour cet utilisateur');
    return res.status(404).json({ message: 'Aucune question trouvée pour cet utilisateur.' });
  }

  console.log('✅ Question retournée :', user.security.question);
  return res.json({ question: user.security.question });
});

///////////////////////////////////////// MAJ MDP QUESTION SECRETE ///////////////////////////////////////////////////

// Route POST n°3_Client // Réinitialise le mot de passe après vérification de la réponse à la question secrète
// 🔒 Vérifie email, réponse à la question secrète et nouveau mot de passe
// ⚠️ Bloque après 3 tentatives erronées (compte temporairement bloqué)
// 🔐 Hash du nouveau mot de passe avec bcrypt avant sauvegarde
// 📂 Met à jour le fichier USERS_FILE avec le nouveau mot de passe hashé
app.post('/reset-password', async (req, res) => {
  console.log('🚦 Requête reçue: POST /reset-password');
  const { email, answer, newPassword } = req.body;
  console.log('📩 Requête de reset reçue pour:', email);

  if (!email || !answer || !newPassword) {
    return res.status(400).json({ message: 'Champs manquants' });
  }

  let users = [];
  if (fs.existsSync(USERS_FILE)) {
    users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  }

  console.log('📚 Emails existants:', users.map(u => u.email));

  const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());

  if (!user) {
    console.log('❌ Utilisateur non trouvé');
    return res.status(404).json({ message: 'Utilisateur introuvable.' });
  }

  if (!user.securityAnswer) {
    return res.status(400).json({ message: 'Aucune réponse de sécurité enregistrée.' });
  }

  if (!attempts[email]) attempts[email] = 0;
  if (attempts[email] >= 3) {
    return res.status(403).json({ message: 'Trop de tentatives. Compte temporairement bloqué.' });
  }

  if (user.securityAnswer.toLowerCase() !== answer.toLowerCase()) {
    attempts[email]++;
    console.log('❌ Réponse incorrecte. Tentative :', attempts[email]);
    return res.status(403).json({ message: 'Réponse incorrecte.' });
  }

  // Réponse correcte
  attempts[email] = 0;
  const hashedPassword = await bcrypt.hash(newPassword, 10);
  user.password = hashedPassword;

  const updatedUsers = users.map(u => (u.email === user.email ? user : u));
  fs.writeFileSync(USERS_FILE, JSON.stringify(updatedUsers, null, 2));

  console.log('✅ Mot de passe mis à jour avec succès');
  res.json({ message: 'Mot de passe mis à jour avec succès.' });
});

////////////////////////////////////////// MAJ MDP SIMPLE ///////////////////////////////////////////////////

// Route POST n°4_Client // Mise à jour du mot de passe dans le profil client
// 🔒 Vérifie l’email via paramètre d’URL et valide le mot de passe actuel
// ⚠️ Refuse la modification si le mot de passe actuel est incorrect
// 🔐 Hash le nouveau mot de passe avec bcrypt avant sauvegarde
// 📂 Met à jour le fichier USERS_FILE avec le nouveau mot de passe hashé
app.post('/dossier/:email/change-password', async (req, res) => {
  const email = req.params.email.toLowerCase();
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ message: 'Champs manquants' });
  }

  let users = [];
  if (fs.existsSync(USERS_FILE)) {
    users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  }

  const user = users.find(u => u.email.toLowerCase() === email);
  if (!user) {
    return res.status(404).json({ message: 'Utilisateur non trouvé.' });
  }

  // Vérification du mot de passe actuel
  const validPassword = await bcrypt.compare(currentPassword, user.password);
  if (!validPassword) {
    return res.status(403).json({ message: 'Mot de passe actuel incorrect.' });
  }

  // Hash du nouveau mot de passe
  const hashedPassword = await bcrypt.hash(newPassword, 10);
  user.password = hashedPassword;

  // Sauvegarde des données mises à jour dans USERS_FILE
  const updatedUsers = users.map(u => (u.email === user.email ? user : u));
  fs.writeFileSync(USERS_FILE, JSON.stringify(updatedUsers, null, 2));

  return res.json({ message: 'Mot de passe changé avec succès.' });
});

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////// FIN CLIENT ///////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////









//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// GET RECUPERATION DES INFOS ///////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Route GET n°1 // CoachListClient.jsx

// 🔍 Route GET pour récupérer tous les dossiers clients côté coach
app.get('/dossiers', (req, res) => {
  const dossiersDir = path.join(__dirname, 'data', 'dossiers');

  // 🔁 Lecture du dossier contenant tous les fichiers clients
  fs.readdir(dossiersDir, (err, files) => {
    if (err) {
      console.error('❌ Erreur lecture du dossier clients :', err);
      return res.status(500).json({ message: 'Erreur serveur lors de la lecture des dossiers clients.' });
    }

    // 🧹 Filtrage uniquement des fichiers .json (chaque fichier représente un client)
    const dossiers = files
      .filter(file => file.endsWith('.json'))
      .map(file => {
        const filePath = path.join(dossiersDir, file);

        try {
          const content = fs.readFileSync(filePath, 'utf-8');
          return JSON.parse(content);
        } catch (err) {
          console.error(`⚠️ Erreur parsing JSON pour le fichier ${file} :`, err);
          return null; // En cas d'erreur, on retourne null
        }
      })
      .filter(dossier => dossier !== null); // 🔐 On supprime les éléments null du tableau final

    // ✅ Réponse : envoi de la liste complète des dossiers
    res.json(dossiers);
  });
});

//////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Route POST n°1 BIS // CoachListClient.jsx – Génération du token client
app.post('/api/generate-client-token', authenticateToken, (req, res) => {
  console.log("🔐 [Backend] /api/generate-client-token appelé");

  // ✅ Extraction des infos du coach depuis le token (via middleware authenticateToken)
  const requestingUser = req.user; // Contient { email, role }
  console.log("🔍 [Backend] utilisateur demandeur (coach):", requestingUser);

  // 📨 Email du client fourni dans le body de la requête
  const { clientEmail } = req.body;
  console.log("📧 [Backend] email client reçu:", clientEmail);

  // ⛔️ Vérification : email du client obligatoire
  if (!clientEmail) {
    console.log("❌ [Backend] Pas d'email client fourni");
    return res.status(400).json({ message: 'Email client manquant' });
  }

  // ⛔️ Vérification : seul un coach peut générer un token pour un client
  if (requestingUser.role !== 'coach') {
    console.log("⛔️ [Backend] accès refusé : utilisateur n'est pas coach");
    return res.status(403).json({ message: 'Accès refusé : vous devez être coach.' });
  }

  // 🔐 Préparation du payload pour le token client (avec rôle 'client')
  const clientPayload = {
    email: clientEmail,
    role: 'client',
  };

  // 🕒 Génération du token JWT pour le client, valable 45 minutes
  const tokenClient = jwt.sign(
    clientPayload,
    process.env.JWT_SECRET || 'secret123', // ⚠️ Utiliser une vraie variable d’environnement en prod
    { expiresIn: '45m' }
  );

  console.log("✅ [Backend] Token client généré:", tokenClient);

  // 📤 Envoi du token au frontend
  res.json({ tokenClient });
});

/////////////////////////////////////////////////////////////////////////////////////////////////////
// Route GET n°2 // Récupération des informations complètes d’un client
// 📄 Récupère le dossier JSON complet d’un client via son email

app.get('/dossier/:email', (req, res) => {
  const { email } = req.params;

  // 🧼 Sécurisation du nom de fichier en remplaçant les caractères spéciaux
  const sanitizedEmail = email.replace(/[@.]/g, '_');
  const dossierPath = path.join(dossiersPath, `${sanitizedEmail}.json`);

  console.log("📂 Recherche du fichier client :", dossierPath);

  // ❌ Vérification de l'existence du fichier
  if (!fs.existsSync(dossierPath)) {
    console.warn("🚫 Fichier introuvable pour :", sanitizedEmail);
    return res.status(404).json({ message: 'Dossier non trouvé.' });
  }

  try {
    // 📖 Lecture et parsing du fichier JSON
    const data = fs.readFileSync(dossierPath, 'utf-8');
    const dossier = JSON.parse(data);

    // ✅ Renvoi du contenu complet du dossier client
    res.json(dossier);

  } catch (err) {
    console.error("💥 Erreur lecture/parsing du dossier client :", err);
    res.status(500).json({ message: "Erreur lors de la récupération du dossier client." });
  }
});


/////////////////////////////////////////////////////////////////////////////////////////////////////
// Route GET n°3 // Récupération des entrainements d’un client
// 🏋️‍♂️ Renvoie uniquement le tableau des entrainements du client

app.get('/dossier/:email/entrainements', (req, res) => {
  const { email } = req.params;

  // 🧼 Nettoyage de l'email pour un nom de fichier safe
  const sanitizedEmail = email.replace(/[@.]/g, '_');
  const dossierPath = path.join(dossiersPath, `${sanitizedEmail}.json`);

  // ❌ Vérifie si le fichier existe
  if (!fs.existsSync(dossierPath)) {
    console.warn("❌ Dossier introuvable pour :", sanitizedEmail);
    return res.status(404).json({ message: "Dossier non trouvé." });
  }

  try {
    // 📖 Lecture du fichier JSON
    const data = fs.readFileSync(dossierPath, 'utf-8');
    const dossier = JSON.parse(data);

    // ✅ Envoi uniquement des entrainements
    res.json(dossier.entrainements || []);

  } catch (err) {
    console.error("💥 Erreur lecture/parsing entrainements :", err);
    res.status(500).json({ message: "Erreur serveur lors de la récupération des entrainements." });
  }
});

/////////////////////////////////////////////////////////////////////////////////////////////////////
// Route GET n°4 // Récupération des diètes d’un client
// 🍽️ Renvoie uniquement le tableau des diètes du client

app.get('/dossier/:email/dietes', (req, res) => {
  const rawEmail = req.params.email;

  // 🔓 Décodage d’un email encodé dans l’URL (ex: %40 pour @)
  const decodedEmail = decodeURIComponent(rawEmail);

  // 🧼 Remplacement des caractères spéciaux pour générer un nom de fichier valide
  const sanitizedEmail = decodedEmail.replace(/[@.]/g, '_');
  const dossierPath = path.join(dossiersPath, `${sanitizedEmail}.json`);

  // ❌ Vérifie l’existence du fichier
  if (!fs.existsSync(dossierPath)) {
    console.error('❌ Fichier introuvable:', dossierPath);
    return res.status(404).json({ message: "Dossier non trouvé." });
  }

  try {
    // 📖 Lecture du fichier
    const data = fs.readFileSync(dossierPath, 'utf-8');

    // 🚫 Vérifie si le fichier est vide
    if (!data || data.trim().length === 0) {
      console.error('📛 Fichier JSON vide !');
      return res.status(400).json({ message: "Fichier vide." });
    }

    // 🔍 Parse du JSON
    const dossier = JSON.parse(data);

    // 🚫 Vérifie si la clé "dietes" existe
    if (!dossier.dietes) {
      console.error('🚫 Clé "dietes" manquante dans le dossier');
      return res.status(400).json({ message: 'Clé "dietes" absente dans le dossier.' });
    }

    // ✅ Réponse avec les diètes
    res.json(dossier.dietes);

  } catch (err) {
    console.error('💥 Erreur lecture/parse JSON:', err.message);
    return res.status(400).json({ message: "Erreur traitement dossier.", error: err.message });
  }
});


/////////////////////////////////////////////////////////////////////////////////////////////////////
// Route GET n°5 // Récupération des mensurations d’un client
// 📏 Renvoie uniquement le tableau des mensurations du dossier client

app.get('/dossier/:email/mensurations', (req, res) => {
  const { email } = req.params;

  // 🧼 Sanitize l'email pour créer un nom de fichier sécurisé
  const sanitizedEmail = email.replace(/[@.]/g, '_');
  const dossierPath = path.join(dossiersPath, `${sanitizedEmail}.json`);

  // ❌ Vérifie que le fichier du dossier client existe
  if (!fs.existsSync(dossierPath)) {
    console.warn(`🚫 Dossier introuvable pour : ${sanitizedEmail}`);
    return res.status(404).json({ message: "Dossier non trouvé." });
  }

  try {
    // 📖 Lecture et parsing du fichier
    const data = fs.readFileSync(dossierPath);
    const dossier = JSON.parse(data);

    // ✅ Envoi des mensurations seulement
    res.json(dossier.mensurations);
  } catch (err) {
    console.error('💥 Erreur lors de la lecture du fichier JSON :', err.message);
    res.status(500).json({ message: "Erreur lors de la récupération des mensurations." });
  }
});

////////////////////////////////////////// SUIVI DIETES ///////////////////////////////////////////////////////

app.get('/dossier/:email/suividiete', (req, res) => {
  const email = req.params.email;
  const sanitizedEmail = email.replace(/[@.]/g, '_');
  const dossierPath = path.join(dossiersPath, `${sanitizedEmail}.json`);

  if (!fs.existsSync(dossierPath)) {
    return res.status(404).json({ error: 'Utilisateur non trouvé.' });
  }

  const clientData = JSON.parse(fs.readFileSync(dossierPath, 'utf-8'));
  const suivi = clientData.suiviDiete || {};

  res.json(suivi);
});

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// POST AJOUTER DES INFOS ///////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////










///////////////////////////////////////// MENSURATIONS /////////////////////////////////////////////////////

// Route POST n°1 // Ajout d'une nouvelle mensuration dans le dossier client
// 🔒 Protégée par un token (authenticateToken)
// 📸 Permet l’upload de photos : face, dos, profil droit et gauche

app.post(
  '/dossier/:email/mensurations',
  authenticateToken,
  upload.fields([
    { name: 'photoFace' }, 
    { name: 'photoDos' },
    { name: 'photoProfilD' }, 
    { name: 'photoProfilG' }
  ]),
  (req, res) => {
    const rawEmail = req.params.email;




    const tokenEmail = req.user?.email;

    if (!tokenEmail || tokenEmail !== rawEmail) {
      console.warn(`❌ Accès interdit. Email dans le token (${tokenEmail}) ≠ cible (${rawEmail})`);
      return res.status(403).json({ message: 'Accès interdit : token ne correspond pas à l’email cible.' });
    }



    const sanitizedEmail = rawEmail.replace(/[@.]/g, '_');
    const dossierPath = path.join(dossiersPath, `${sanitizedEmail}.json`);

    // 🔍 Vérification de l’existence du dossier client
    if (!fs.existsSync(dossierPath)) {
      console.warn(`❌ Dossier client introuvable : ${sanitizedEmail}`);
      return res.status(404).json({ message: 'Dossier client introuvable.' });
    }

    // 📖 Lecture du fichier client
    const dossier = JSON.parse(fs.readFileSync(dossierPath, 'utf-8'));

    // 🆕 Création de la nouvelle entrée mensuration
    const newEntry = {
      date: req.body.date,
      poids: req.body.poids || '',
      poitrine: req.body.poitrine || '',
      taille: req.body.taille || '',
      hanches: req.body.hanches || '',
      brasD: req.body.brasD || '',
      brasG: req.body.brasG || '',
      cuisseD: req.body.cuisseD || '',
      cuisseG: req.body.cuisseG || '',
      molletD: req.body.molletD || '',
      molletG: req.body.molletG || '',
      photoFace: req.files['photoFace'] ? `/uploads/${req.files['photoFace'][0].filename}` : null,
      photoDos: req.files['photoDos'] ? `/uploads/${req.files['photoDos'][0].filename}` : null,
      photoProfilD: req.files['photoProfilD'] ? `/uploads/${req.files['photoProfilD'][0].filename}` : null,
      photoProfilG: req.files['photoProfilG'] ? `/uploads/${req.files['photoProfilG'][0].filename}` : null,
    };

    // 🧹 Nettoyage (supprime les null éventuels) + ajout de la nouvelle entrée en début de tableau
    dossier.mensurations = dossier.mensurations.filter(Boolean);
    dossier.mensurations.unshift(newEntry);

    // 💾 Écriture du fichier mis à jour
    fs.writeFileSync(dossierPath, JSON.stringify(dossier, null, 2));

    // ✅ Réponse succès
    res.status(201).json({
      message: 'Mensuration ajoutée avec succès.',
      data: newEntry
    });
  }
);












///////////////////////////////////////// ENTRAINEMENTS /////////////////////////////////////////////////////

// Route POST n°2 // Enregistrement d’un ou plusieurs entraînements pour un client
// 📥 Reçoit un email + tableau d’entrainements dans le corps de la requête
// 🆔 Génère un nouvel ID UUID pour chaque entraînement et performance créée
// 🏋️‍♂️ Gère les types d’entraînements classiques et cross-training (avec circuits)
// 🔄 Met à jour les listes entrainements et performances dans le dossier client
// ⚠️ Nécessite que le dossier client existe sinon renvoie 404
app.post('/RouteEnregistrementTraing', (req, res) => {
  console.log('Body reçu:', req.body);
  try {
    const { email, entrainements } = req.body;

    // Validation des données reçues
    if (!email) return res.status(400).json({ error: 'Email requis.' });
    if (!Array.isArray(entrainements) || entrainements.length === 0) {
      return res.status(400).json({ error: 'Entraînement vide.' });
    }

    const sanitizedEmail = email.replace(/[@.]/g, '_');
    const dossierPath = path.join(dossiersPath, `${sanitizedEmail}.json`);

    if (!fs.existsSync(dossierPath)) {
      return res.status(404).json({ error: 'Utilisateur non trouvé.' });
    }

    const clientData = JSON.parse(fs.readFileSync(dossierPath));
    clientData.entrainements = clientData.entrainements || [];
    clientData.performances = clientData.performances || [];

    entrainements.forEach((entraînement) => {
      const {
        date,
        muscle1,
        muscle2,
        muscle3,
        typeTraining = '',
        exercices = [],
        noteTraining = '',
      } = entraînement;

      if (typeTraining === 'cross-training') {
        const newId = uuidv4();

        // Formatage spécifique pour circuits cross-training
        const circuitsFormates = exercices.map((circuit) => ({
          nom: circuit.nom,
          tours: circuit.tours,
          on: circuit.on,
          off: circuit.off,
          exercices: circuit.exercices,
        }));

        clientData.entrainements.push({
          id: newId,
          date,
          muscle1,
          muscle2,
          muscle3,
          typeTraining,
          exercices: circuitsFormates,
          noteTraining
        });
      } else {
        const newId = uuidv4();

        // Entraînement classique musculation
        clientData.entrainements.push({
          id: newId,
          date,
          muscle1,
          muscle2,
          muscle3,
          typeTraining,
          exercices,
          noteTraining,
        });

        // Ajout des performances associées à chaque exercice
        exercices.forEach((exo) => {
          const perfId = uuidv4();

          clientData.performances.push({
            id: perfId,
            jourS: date,
            nom: exo.nom,
            series: exo.series,
            reps: exo.repetitions,
            charges: [
              {
                date: new Date().toISOString().split('T')[0],
                charge: 0
              }
            ]
          });
        });
      }
    });

    fs.writeFileSync(dossierPath, JSON.stringify(clientData, null, 2));
    res.status(201).json({ message: 'Entraînement enregistré avec succès.' });

  } catch (err) {
    console.error("Erreur serveur RouteEnregistrementTraing:", err);
    res.status(500).json({ error: 'Erreur interne serveur.' });
  }
});

//////////////////////////////////////////// DIETE /////////////////////////////////////////////////////////

// Route POST n°3 // Création ou mise à jour d’une diète dans le dossier client
// 📥 Reçoit email, id (optionnel), date, diete (objet ou tableau), kcalObjectif, mode
// 🔄 Si id fourni, met à jour la diète existante, sinon crée une nouvelle avec un id timestamp
// ⚠️ Vérifie que le dossier client existe sinon renvoie 404
// 📝 Met à jour le fichier JSON du client avec la nouvelle liste de diètes
app.post('/CoachDieteGenerator', (req, res) => {
  try {
    const { email, id, date, diete, kcalObjectif, mode } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email requis.' });
    }

    if (!Array.isArray(diete) && typeof diete !== 'object') {
      return res.status(400).json({ error: 'Diete vide ou invalide.' });
    }

    const sanitizedEmail = email.replace(/[@.]/g, '_');
    const dossierPath = path.join(dossiersPath, `${sanitizedEmail}.json`);

    if (!fs.existsSync(dossierPath)) {
      return res.status(404).json({ error: 'Utilisateur non trouvé.' });
    }

    const clientData = JSON.parse(fs.readFileSync(dossierPath, 'utf-8'));
    if (!Array.isArray(clientData.dietes)) {
      clientData.dietes = [];
    }

    if (id) {
      // Trouver et mettre à jour la diète existante
      const index = clientData.dietes.findIndex(d => d.id === id);
      if (index !== -1) {
        clientData.dietes[index] = { id, date, kcalObjectif, repas: diete };
      } else {
        // Si non trouvée, ajouter nouvelle
        clientData.dietes.push({ id, date, kcalObjectif, repas: diete });
      }
    } else {
      // Pas d'id, créer nouvelle diète avec id timestamp
      const newId = Date.now().toString();
      clientData.dietes.push({ id: newId, date, kcalObjectif, repas: diete });
    }

    fs.writeFileSync(dossierPath, JSON.stringify(clientData, null, 2));

    console.log("Diète sauvegardée avec succès !");
    res.status(201).json({ message: 'Diète sauvegardée avec succès.' });

  } catch (err) {
    console.error("Erreur serveur CoachDieteGenerator:", err);
    res.status(500).json({ error: 'Erreur interne serveur.' });
  }
});

///////////////////////////////////////////// PERFORMANCES /////////////////////////////////////////////////////

// Route POST n°4 // Mise à jour des charges dans les performances d’un client
// 📥 Reçoit email et tableau d’updates { id, charges }
// 🔄 Pour chaque update, remplace les charges de la performance correspondante par les nouvelles valides
// ⚠️ Vérifie que le dossier client existe sinon renvoie 404
// 📝 Enregistre les modifications dans le fichier JSON du client
app.post('/SuiviPerformanceClient', (req, res) => {
  try {
    const { email, updates } = req.body;

    if (!email) return res.status(400).json({ error: 'Email requis.' });
    if (!Array.isArray(updates) || updates.length === 0) {
      return res.status(400).json({ error: 'Aucune mise à jour fournie.' });
    }

    const sanitizedEmail = email.replace(/[@.]/g, '_');
    const dossierPath = path.join(dossiersPath, `${sanitizedEmail}.json`);

    if (!fs.existsSync(dossierPath)) {
      return res.status(404).json({ error: 'Utilisateur non trouvé.' });
    }

    const clientData = JSON.parse(fs.readFileSync(dossierPath));

    updates.forEach(update => {
      const perf = clientData.performances.find(p => p.id === update.id);
      if (perf) {
        // Remplace les anciennes charges par les nouvelles valides
        perf.charges = update.charges.filter(c =>
          c.date &&
          !isNaN(new Date(c.date)) &&
          c.charge !== undefined &&
          c.charge !== null &&
          c.charge !== ''
        );

        console.log(`Charges mises à jour pour performance ID ${update.id}`);
      } else {
        console.warn(`Performance non trouvée pour ID : ${update.id}`);
      }
    });

    fs.writeFileSync(dossierPath, JSON.stringify(clientData, null, 2));
    res.status(200).json({ message: 'Charges mises à jour avec succès.' });
  } catch (err) {
    console.error("Erreur serveur SuiviPerformanceClient:", err);
    res.status(500).json({ error: 'Erreur interne serveur.' });
  }
});

//////////////////////////////////////////// SUIVI CLIENT /////////////////////////////////////////////////////////
// Routes POST n°5 // 

// 📌 Initialiser la journée de suiviDiete si elle n'existe pas
app.post('/dossier/:email/suividiete/init', (req, res) => {
  const email = req.params.email;
  if (!email) return res.status(400).json({ error: 'Email requis.' });

  const sanitizedEmail = email.replace(/[@.]/g, '_');
  const dossierPath = path.join(dossiersPath, `${sanitizedEmail}.json`);

  if (!fs.existsSync(dossierPath)) {
    return res.status(404).json({ error: 'Utilisateur non trouvé.' });
  }

  const clientData = JSON.parse(fs.readFileSync(dossierPath, 'utf-8'));
  const currentDate = new Date().toISOString().split('T')[0];

  if (!clientData.suiviDiete) {
    clientData.suiviDiete = {};
  }

  if (clientData.suiviDiete[currentDate]) {
    return res.status(200).json({ message: 'Journée déjà initialisée.' });
  }

  const repasTypes = [
    'matin',
    'collation_matin',
    'midi',
    'collation_aprem',
    'post_training',
    'soir',
    'avant_coucher',
  ];

  const nouveauJour = {
    commentaireJournee: ''
  };

  repasTypes.forEach(type => {
    nouveauJour[type] = {
      commentaire: '',
      aliments: []
    };
  });

  clientData.suiviDiete[currentDate] = nouveauJour;

  fs.writeFileSync(dossierPath, JSON.stringify(clientData, null, 2), 'utf-8');

  return res.status(200).json({
    message: 'Journée ajoutée dans suiviDiete',
    date: currentDate,
    structure: nouveauJour
  });
});











// ⚠️ Route temporaire pour réinitialiser la journée en cours (à supprimer en prod)
app.post('/dossier/:email/suividiete/reset', (req, res) => {
  const email = req.params.email;
  const sanitizedEmail = email.replace(/[@.]/g, '_');
  const dossierPath = path.join(dossiersPath, `${sanitizedEmail}.json`);
  const currentDate = new Date().toISOString().split('T')[0];

  if (!fs.existsSync(dossierPath)) {
    return res.status(404).json({ error: 'Utilisateur non trouvé.' });
  }

  const clientData = JSON.parse(fs.readFileSync(dossierPath, 'utf-8'));

  if (clientData.suiviDiete && clientData.suiviDiete[currentDate]) {
    delete clientData.suiviDiete[currentDate];
    fs.writeFileSync(dossierPath, JSON.stringify(clientData, null, 2), 'utf-8');
    return res.status(200).json({ message: 'Journée supprimée.' });
  }

  return res.status(200).json({ message: 'Aucune journée à supprimer.' });
});

























//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// PUT METTRE A JOUR LES INFOS ///////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////// DIETE /////////////////////////////////////////////////////////

// Route PUT n°1 // Mise à jour d’une diète spécifique dans le dossier client
// 🔒 Protégée (idéalement à sécuriser avec un token)
// 🥗 Met à jour la diète identifiée par son ID dans le dossier JSON du client
// 🗃️ Modifie la date, repas, objectif kcal et mode d’alimentation

app.put('/CoachDossierDiete', (req, res) => {
  try {
    const { id, email, date, diete, kcalObjectif, mode } = req.body;

    // Validation des données reçues
    if (!id) return res.status(400).json({ error: 'ID de la diète requis pour la mise à jour.' });
    if (!email) return res.status(400).json({ error: 'Email requis.' });
    if (!diete) return res.status(400).json({ error: 'Diète vide ou invalide.' });

    // Nettoyage de l'email pour correspondre au nom du fichier JSON
    const sanitizedEmail = email.replace(/[@.]/g, '_');
    const dossierPath = path.join(dossiersPath, `${sanitizedEmail}.json`);

    // Vérification de l'existence du dossier client
    if (!fs.existsSync(dossierPath)) {
      return res.status(404).json({ error: 'Utilisateur non trouvé.' });
    }

    // Lecture du dossier client
    const clientData = JSON.parse(fs.readFileSync(dossierPath, 'utf-8'));
    if (!Array.isArray(clientData.dietes)) {
      clientData.dietes = [];
    }

    // Recherche de la diète par son ID
    const index = clientData.dietes.findIndex(d => d.id === id);

    if (index !== -1) {
      // Mise à jour de la diète existante
      clientData.dietes[index] = {
        id,          // on conserve l'ID d'origine
        date,
        repas: diete,
        kcalObjectif,
        mode
      };
    } else {
      // Si la diète n'existe pas, on renvoie une erreur 404
      return res.status(404).json({ error: 'Diète non trouvée pour cet ID.' });
    }

    // Sauvegarde du dossier mis à jour
    fs.writeFileSync(dossierPath, JSON.stringify(clientData, null, 2));

    console.log("✅ Diète mise à jour avec succès !");
    res.status(200).json({ message: 'Diète mise à jour avec succès.' });

  } catch (err) {
    console.error("💥 Erreur serveur CoachDossierDiete:", err);
    res.status(500).json({ error: 'Erreur interne serveur.' });
  }
});

///////////////////////////////////////// ENTRAINEMENTS /////////////////////////////////////////////////////

// Route PUT n°2 // Mise à jour des entraînements d’un client
// 🏋️‍♂️ Remplace complètement la liste des entraînements dans le dossier client
// 📂 Le dossier client est identifié par l’email (nettoyé pour nom de fichier)
// 🔒 À sécuriser idéalement par un middleware d’authentification
app.put('/CoachDossierEntrainements/:email', (req, res) => {
  const email = req.params.email;
  const { entrainements } = req.body;

  if (!email || !entrainements || !Array.isArray(entrainements)) {
    return res.status(400).json({ error: 'Email ou entraînements invalides' });
  }

  const fileName = email.replace(/[@.]/g, '_') + '.json'; // Sécurise le nom de fichier
  const filePath = path.join(__dirname, 'data', 'dossiers', fileName);

  try {
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: "Fichier utilisateur introuvable" });
    }

    const data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    data.entrainements = entrainements;
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));

    return res.json({ message: 'Entraînements mis à jour avec succès' });
  } catch (error) {
    console.error("Erreur lors de la mise à jour :", error);
    return res.status(500).json({ error: "Erreur serveur : " + error.message });
  }
});

///////////////////////////////////////////// PROFIL /////////////////////////////////////////////////////

// Route PUT n°3 // Mise à jour du profil, mensuration et objectifs d’un client
// 🔄 Modifie les premières entrées des tableaux profil, mensurationProfil et objectifs
// 🧾 Les données mises à jour sont extraites du corps de la requête (req.body)
// 📂 Le dossier client est identifié par l’email (sanitize pour le nom de fichier)
// ⚠️ Attention : la gestion des photos conserve l’ancienne si aucune nouvelle n’est fournie
// 🛑 À sécuriser idéalement avec un middleware d’authentification (ex : authenticateToken)
app.put('/dossier/:email', (req, res) => {
  const { email } = req.params;
  const sanitizedEmail = email.replace(/[@.]/g, '_');
  const dossierPath = path.join(dossiersPath, `${sanitizedEmail}.json`);

  // Vérifie que le dossier client existe
  if (!fs.existsSync(dossierPath)) {
    return res.status(404).json({ message: 'Dossier non trouvé.' });
  }

  // Lecture du fichier JSON client
  const data = fs.readFileSync(dossierPath);
  const dossier = JSON.parse(data);

  // Mise à jour des infos du profil client
  dossier.profil[0] = {
    ...dossier.profil[0],  // conserve les autres champs existants
    nom: req.body.nom,
    prenom: req.body.prenom,
    age: req.body.age,
    profession: req.body.profession,
    telephone: req.body.telephone,
    photoProfil: req.body.photoProfil || dossier.profil[0].photoProfil  // garde l’ancienne photo si aucune nouvelle fournie
  };

  // Mise à jour des mensurations de profil
  dossier.mensurationProfil[0] = {
    ...dossier.mensurationProfil[0],
    taille: req.body.taille,
    poids: req.body.poids
  };

  // Mise à jour des objectifs
  dossier.objectifs[0] = {
    ...dossier.objectifs[0],
    objectif: req.body.objectif
  };

  // Enregistrement des modifications dans le fichier JSON
  fs.writeFileSync(dossierPath, JSON.stringify(dossier, null, 2));

  // Réponse de succès
  res.json({ message: 'Profil mis à jour avec succès' });
});

//////////////////////////////////////////////////////////////////////////////////////////////////////////
// Routes PUT n°4 // 
// ✅ Mise à jour d’un repas dans suiviDiete
app.put('/dossier/:email/suividiete/:date/:repasType', (req, res) => {
  const email = req.params.email;
  const sanitizedEmail = email.replace(/[@.]/g, '_');
  const dossierPath = path.join(dossiersPath, `${sanitizedEmail}.json`);

  const { date, repasType } = req.params;
  const { aliments, commentaire } = req.body;

  if (!fs.existsSync(dossierPath)) {
    return res.status(404).json({ error: 'Utilisateur non trouvé.' });
  }

  const clientData = JSON.parse(fs.readFileSync(dossierPath, 'utf-8'));

  if (!clientData.suiviDiete || !clientData.suiviDiete[date]) {
    return res.status(400).json({ error: 'Journée non initialisée.' });
  }

  // Vérifie si le type de repas est valide
  const repas = clientData.suiviDiete[date].repas;
  if (!repas[repasType]) {
    return res.status(400).json({ error: `Type de repas invalide : ${repasType}` });
  }

  repas[repasType] = {
    aliments: aliments || [],
    commentaire: commentaire || ''
  };

  fs.writeFileSync(dossierPath, JSON.stringify(clientData, null, 2), 'utf-8');

  return res.status(200).json({ message: 'Repas mis à jour avec succès.' });
});

//////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////// FIN DE TOUTES LES ROUTES //////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////



/////////////////////////////////////////////////////////////////////////////////////////////////////

// 💥 Gestion des erreurs -> TOUJOURS EN DERNIER !!!!!
app.use((err, req, res, next) => {
  console.error('💥 Erreur Express :', err.stack);
  res.status(500).json({ message: 'Erreur interne du serveur.' });
});

/////////////////////////////////////////////////////////////////////////////////////////////////////

// Route finale : démarrage du serveur
app.listen(PORT, () => {
  console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`);
});

