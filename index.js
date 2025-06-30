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


/////////////////////////////////////////////////////////////////////////////////////////////////////
const admin = require('firebase-admin');

const serviceAccount = JSON.parse(process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
/////////////////////////////////////////////////////////////////////////////////////////////////////








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

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
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

app.post('/login', async (req, res) => {
  let { email, password } = req.body;

  // 🧼 Nettoyage de l'email pour éviter les erreurs de saisie
  email = email.trim().toLowerCase();

  // 🔐 Connexion spéciale "coach admin" en dur
  if (email === 'coach@admin.com' && password === 'coach123') {
    const token = jwt.sign(
      { email, role: 'coach' },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    return res.json({ message: "Connexion coach réussie", token });
  }

  try {
    // 🔍 Recherche utilisateur dans Firestore
    const usersRef = db.collection('users');
    const snapshot = await usersRef.where('email', '==', email).limit(1).get();

    if (snapshot.empty) {
      return res.status(400).json({ message: "Utilisateur non trouvé." });
    }

    const userDoc = snapshot.docs[0];
    const user = userDoc.data();

    // 🔑 Vérification du mot de passe (version async non bloquante)
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ message: "Mot de passe incorrect." });
    }

    // ✅ Authentification réussie — génération du token
    const token = jwt.sign(
      {
        email: user.email,
        role: 'client',
        uid: userDoc.id // ID Firestore utile pour les accès directs plus tard
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ message: "Connexion réussie", token });

  } catch (error) {
    console.error("🔥 Erreur lors de la connexion :", error);
    res.status(500).json({ message: "Erreur serveur." });
  }
});
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////// FIN GENERAL ///////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////


















//////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////// COTE CLIENT ///////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

// 🧍‍♂️ Route POST n°1_Client — Inscription d'un client

app.post('/register', async (req, res) => {
  console.log("📥 Requête reçue pour l'inscription d'un nouveau client");

  const {
    email, password,
    securityQuestion, securityAnswer,
    profil, mensurationProfil, hygieneVie, objectifs,
    medical, physio, nutrition, activite,
    preference
  } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email et mot de passe requis.' });
  }

  // Fonction pour transformer l'email en ID Firestore
  const emailToId = (email) => email.toLowerCase().replace(/[@.]/g, '_');
  const userId = emailToId(email);

  try {
    const userDocRef = db.collection('users').doc(userId);
    const userDoc = await userDocRef.get();

    if (userDoc.exists) {
      return res.status(409).json({ message: 'Utilisateur déjà existant.' });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);

    // Créer le document utilisateur dans users collection
    await userDocRef.set({
      email,
      password: hashedPassword,
      security: {
        question: securityQuestion,
        answer: securityAnswer
      }
    });

    // Construire le dossier_client
    const dossierClient = {
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
      mensurations: [],
      entrainements: [],
      performances: [],
      dietes: []
    };

    // Créer la sous-collection dossier_client avec un document userId
    await userDocRef.collection('dossier_client').doc(userId).set(dossierClient);

    res.status(201).json({ message: 'Utilisateur enregistré avec succès.', userId });

  } catch (error) {
    console.error("❌ Erreur lors de l'inscription :", error);
    res.status(500).json({ message: "Erreur lors de l'inscription." });
  }
});

////////////////////////////////////////// QUESTION SECRETE ///////////////////////////////////////////////////

// Route POST n°2_Client // Vérifie et retourne la question secrète d’un utilisateur
// 🔍 Reçoit l’email et recherche l’utilisateur dans USERS_FILE
// ⚠️ Vérifie que l’email est fourni et que le fichier utilisateurs existe
// ❌ Renvoie 404 si utilisateur ou question secrète absente
// ✅ Renvoie la question secrète pour l’utilisateur trouvé
app.post('/verify-security-question', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Email requis.' });
  }

  try {
    const usersRef = db.collection('users');
    const snapshot = await usersRef.where('email', '==', email.trim().toLowerCase()).limit(1).get();

    if (snapshot.empty) {
      return res.status(404).json({ message: 'Utilisateur non trouvé.' });
    }

    const userDoc = snapshot.docs[0];
    const user = userDoc.data();

    if (!user.security || !user.security.question) {
      return res.status(404).json({ message: 'Aucune question trouvée pour cet utilisateur.' });
    }

    console.log('✅ Question retournée :', user.security.question);
    return res.json({ question: user.security.question });

  } catch (error) {
    console.error('❌ Erreur lors de la récupération de la question :', error);
    res.status(500).json({ message: 'Erreur serveur.' });
  }
});


///////////////////////////////////////// MAJ MDP QUESTION SECRETE ///////////////////////////////////////////////////

// Route POST n°3_Client // Réinitialise le mot de passe après vérification de la réponse à la question secrète
// 🔒 Vérifie email, réponse à la question secrète et nouveau mot de passe
// ⚠️ Bloque après 3 tentatives erronées (compte temporairement bloqué)
// 🔐 Hash du nouveau mot de passe avec bcrypt avant sauvegarde
// 📂 Met à jour le fichier USERS_FILE avec le nouveau mot de passe hashé
app.post('/reset-password', async (req, res) => {
  console.log('🚦 Requête reçue: POST /reset-password');

  // Récupérer email depuis le body, pas depuis req.user
  const { email, answer, newPassword } = req.body;

  if (!email || !answer || !newPassword) {
    return res.status(400).json({ message: 'Champs manquants' });
  }

  try {
    // Adaptation si tu utilises email pour construire l’ID Firestore
    const userId = email.toLowerCase().replace(/[@.]/g, '_');
    const userDocRef = db.collection('users').doc(userId);
    const userDoc = await userDocRef.get();

    if (!userDoc.exists) {
      console.log('❌ Utilisateur introuvable');
      return res.status(404).json({ message: 'Utilisateur introuvable.' });
    }

    const userData = userDoc.data();

    if (!userData.security || !userData.security.answer) {
      return res.status(400).json({ message: 'Aucune réponse de sécurité enregistrée.' });
    }

    if (userData.security.answer.toLowerCase() !== answer.toLowerCase()) {
      console.log('❌ Réponse incorrecte');
      return res.status(403).json({ message: 'Réponse incorrecte.' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await userDocRef.update({ password: hashedPassword });

    console.log('✅ Mot de passe mis à jour avec succès');
    res.json({ message: 'Mot de passe mis à jour avec succès.' });

  } catch (error) {
    console.error('❌ Erreur lors du reset password :', error);
    res.status(500).json({ message: "Erreur serveur lors de la mise à jour du mot de passe." });
  }
});

////////////////////////////////////////// MAJ MDP SIMPLE ///////////////////////////////////////////////////

// Route POST n°4_Client // Mise à jour du mot de passe dans le profil client
// 🔒 Vérifie l’email via paramètre d’URL et valide le mot de passe actuel
// ⚠️ Refuse la modification si le mot de passe actuel est incorrect
// 🔐 Hash le nouveau mot de passe avec bcrypt avant sauvegarde
// 📂 Met à jour le fichier USERS_FILE avec le nouveau mot de passe hashé
app.post('/dossier/change-password', authenticateToken, async (req, res) => {
  const email = req.user.email.toLowerCase();
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

  const validPassword = await bcrypt.compare(currentPassword, user.password);
  if (!validPassword) {
    return res.status(403).json({ message: 'Mot de passe actuel incorrect.' });
  }

  const hashedPassword = await bcrypt.hash(newPassword, 10);
  user.password = hashedPassword;

  const updatedUsers = users.map(u => (u.email.toLowerCase() === user.email.toLowerCase() ? user : u));
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
// ✅ Route Firestore : Récupération du dossier du client connecté (via req.user.uid)
app.get('/dossier', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.uid; // <-- On part du principe que l'ID doc Firestore est l'UID Firebase

    console.log("📂 Recherche Firestore du dossier client pour :", userId);

    // 🔎 Référence vers le document utilisateur
    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      console.warn("🚫 Utilisateur introuvable :", userId);
      return res.status(404).json({ message: 'Utilisateur non trouvé.' });
    }

    // 🔎 Référence vers la sous-collection dossier_client et le document avec le même ID
    const dossierRef = userRef.collection('dossier_client').doc(userId);
    const dossierDoc = await dossierRef.get();

    if (!dossierDoc.exists) {
      console.warn("🚫 Dossier client introuvable pour :", userId);
      return res.status(404).json({ message: 'Dossier client non trouvé.' });
    }

    const dossierData = dossierDoc.data();

    // ✅ Envoi du contenu du dossier client
    res.json(dossierData);

  } catch (error) {
    console.error("💥 Erreur Firestore lors de la récupération du dossier client :", error);
    res.status(500).json({ message: 'Erreur lors de la récupération du dossier client.' });
  }
});

//////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Route POST n°1 BIS // CoachListClient.jsx – Génération du token client
app.post('/api/generate-client-token', authenticateToken, (req, res) => {
  console.log("🔐 [Backend] /api/generate-client-token appelé");

  const requestingUser = req.user; // { email, role, uid }
  console.log("🔍 [Backend] utilisateur demandeur (coach):", requestingUser);

  // Modification : suppression de la récupération de clientEmail depuis req.body
  // On utilise directement req.user.uid (client authentifié)
  
  // Vérification rôle coach obligatoire
  if (requestingUser.role !== 'coach') {
    console.log("⛔️ [Backend] accès refusé : utilisateur n'est pas coach");
    return res.status(403).json({ message: 'Accès refusé : vous devez être coach.' });
  }

  // Utilisation du uid au lieu d’email pour le payload client
  const clientPayload = {
    uid: requestingUser.uid, // <-- ligne modifiée
    role: 'client',
  };

  const tokenClient = jwt.sign(
    clientPayload,
    process.env.JWT_SECRET || 'secret123',
    { expiresIn: '45m' }
  );

  console.log("✅ [Backend] Token client généré:", tokenClient);

  res.json({ tokenClient });
});


/////////////////////////////////////////////////////////////////////////////////////////////////////
// Route GET n°3 // Récupération des entrainements d’un client
// 🏋️‍♂️ Renvoie uniquement le tableau des entrainements du client

app.get('/dossier/entrainements', authenticateToken, async (req, res) => {
  try {
    // Récupération de l'email utilisateur depuis le token (middleware authenticateToken doit définir req.user)
    const email = req.user.email.toLowerCase();
    const sanitizedEmail = email.replace(/[@.]/g, '_');

    console.log("📂 Recherche des entraînements pour :", sanitizedEmail);

    // Référence vers le document utilisateur
    const userRef = db.collection('users').doc(sanitizedEmail);

    // Référence vers le dossier client (dans la sous-collection)
    const dossierRef = userRef.collection('dossier_client').doc(sanitizedEmail);
    const dossierDoc = await dossierRef.get();

    if (!dossierDoc.exists) {
      console.warn("❌ Dossier client introuvable pour :", sanitizedEmail);
      return res.status(404).json({ message: "Dossier client non trouvé." });
    }

    const dossierData = dossierDoc.data();

    // Envoi uniquement du tableau des entraînements
    res.json(dossierData.entrainements || []);

  } catch (error) {
    console.error("💥 Erreur lors de la récupération des entraînements :", error);
    res.status(500).json({ message: "Erreur serveur lors de la récupération des entraînements." });
  }
});

/////////////////////////////////////////////////////////////////////////////////////////////////////
// Route GET n°4 // Récupération des diètes d’un client
// 🍽️ Renvoie uniquement le tableau des diètes du client

app.get('/dossier/dietes', authenticateToken, async (req, res) => {
  try {
    // Récupération de l'email utilisateur depuis le token (middleware authenticateToken doit définir req.user)
    const email = req.user.email.toLowerCase();
    const sanitizedEmail = email.replace(/[@.]/g, '_');

    console.log("📂 Requête de récupération des diètes pour :", sanitizedEmail);

    const dossierRef = db
      .collection('users')
      .doc(sanitizedEmail)
      .collection('dossier_client')
      .doc(sanitizedEmail);

    const dossierSnap = await dossierRef.get();

    if (!dossierSnap.exists) {
      console.error('❌ Document Firestore introuvable pour :', sanitizedEmail);
      return res.status(404).json({ message: "Dossier non trouvé." });
    }

    const dossier = dossierSnap.data();

    if (!dossier.dietes) {
      console.error('🚫 Clé "dietes" absente dans le document Firestore');
      return res.status(400).json({ message: 'Clé "dietes" absente dans le dossier.' });
    }

    res.json(dossier.dietes);

  } catch (err) {
    console.error('💥 Erreur récupération/parse Firestore :', err.message);
    return res.status(500).json({ message: "Erreur serveur lors du traitement du dossier.", error: err.message });
  }
});


/////////////////////////////////////////////////////////////////////////////////////////////////////
// Route GET n°5 // Récupération des mensurations d’un client
// 📏 Renvoie uniquement le tableau des mensurations du dossier client

app.get('/dossier/mensurations', authenticateToken, async (req, res) => {
  try {
    const email = req.user.email.toLowerCase();
    const sanitizedEmail = email.replace(/[@.]/g, '_');

    console.log(`📦 Requête mensurations pour : ${sanitizedEmail}`);

    const dossierRef = db
      .collection('users')
      .doc(sanitizedEmail)
      .collection('dossier_client')
      .doc(sanitizedEmail);

    const dossierSnap = await dossierRef.get();

    if (!dossierSnap.exists) {
      console.warn(`🚫 Dossier introuvable pour : ${sanitizedEmail}`);
      return res.status(404).json({ message: "Dossier non trouvé." });
    }

    const dossier = dossierSnap.data();

    if (!dossier.mensurations) {
      console.warn(`❌ Clé "mensurations" absente pour : ${sanitizedEmail}`);
      return res.status(400).json({ message: 'Clé "mensurations" absente dans le dossier.' });
    }

    res.json(dossier.mensurations);

  } catch (err) {
    console.error('💥 Erreur Firestore - récupération des mensurations :', err.message);
    res.status(500).json({ message: "Erreur lors de la récupération des mensurations.", error: err.message });
  }
});

////////////////////////////////////////// SUIVI DIETES ///////////////////////////////////////////////////////

app.get('/dossier/suividiete', authenticateToken, async (req, res) => {
  try {
    const email = req.user.email.toLowerCase();
    const sanitizedEmail = email.replace(/[@.]/g, '_');

    console.log(`📥 Requête suivi diète pour : ${sanitizedEmail}`);

    const dossierRef = db
      .collection('users')
      .doc(sanitizedEmail)
      .collection('dossier_client')
      .doc(sanitizedEmail);

    const dossierSnap = await dossierRef.get();

    if (!dossierSnap.exists) {
      console.warn(`🚫 Utilisateur non trouvé : ${sanitizedEmail}`);
      return res.status(404).json({ error: 'Utilisateur non trouvé.' });
    }

    const clientData = dossierSnap.data();
    const suivi = clientData.suiviDiete || {}; // Retourne un objet vide si inexistant

    console.log(`✅ Suivi diète récupéré pour ${sanitizedEmail}`);
    res.json(suivi);

  } catch (err) {
    console.error(`💥 Erreur Firestore - suivi diète :`, err.message);
    res.status(500).json({ error: 'Erreur lors de la récupération du suivi diète.' });
  }
});


app.post('/dossier/performances', authenticateToken, async (req, res) => {
  try {
    const email = req.user.email.toLowerCase();
    const { updates } = req.body;

    // 🧪 Vérification des données
    if (!Array.isArray(updates) || updates.length === 0) {
      return res.status(400).json({ error: 'Aucune mise à jour fournie.' });
    }

    const sanitizedEmail = email.replace(/[@.]/g, '_');
    const dossierRef = db
      .collection('users')
      .doc(sanitizedEmail)
      .collection('dossier_client')
      .doc(sanitizedEmail);

    const docSnap = await dossierRef.get();
    if (!docSnap.exists) {
      return res.status(404).json({ error: 'Utilisateur non trouvé.' });
    }

    const clientData = docSnap.data() || {};
    const performances = Array.isArray(clientData.performances) ? [...clientData.performances] : [];

    // 🔁 Mise à jour des performances
    updates.forEach(update => {
      const perf = performances.find(p => p.id === update.id);
      if (perf) {
        perf.charges = update.charges.filter(c =>
          c.date &&
          !isNaN(new Date(c.date)) &&
          c.charge !== undefined &&
          c.charge !== null &&
          c.charge !== ''
        );
        console.log(`✅ Charges mises à jour pour performance ID ${update.id}`);
      } else {
        console.warn(`⚠️ Performance non trouvée pour ID : ${update.id}`);
      }
    });

    // 💾 Sauvegarde
    await dossierRef.update({ performances });

    res.status(200).json({ message: 'Charges mises à jour avec succès.' });

  } catch (err) {
    console.error("💥 Erreur Firestore SuiviPerformanceClient:", err.message);
    res.status(500).json({ error: 'Erreur interne serveur.' });
  }
});
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// POST AJOUTER DES INFOS ///////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////










///////////////////////////////////////// MENSURATIONS /////////////////////////////////////////////////////

// Route POST n°1 // Ajout d'une nouvelle mensuration dans le dossier client
// 🔒 Protégée par un token (authenticateToken)
// 📸 Permet l’upload de photos : face, dos, profil droit et gauche

app.post(
  '/dossier/mensurations',
  authenticateToken,
  upload.fields([
    { name: 'photoFace' },
    { name: 'photoDos' },
    { name: 'photoProfilD' },
    { name: 'photoProfilG' }
  ]),
  async (req, res) => {
    try {
      const tokenEmail = req.user?.email;

      if (!tokenEmail) {
        console.warn('❌ Token utilisateur absent.');
        return res.status(403).json({ message: 'Accès interdit : token invalide.' });
      }

      const sanitizedEmail = tokenEmail.toLowerCase().replace(/[@.]/g, '_');
      const dossierRef = db
        .collection('users')
        .doc(sanitizedEmail)
        .collection('dossier_client')
        .doc(sanitizedEmail);

      const docSnap = await dossierRef.get();

      if (!docSnap.exists) {
        console.warn(`❌ Dossier introuvable pour : ${sanitizedEmail}`);
        return res.status(404).json({ message: 'Dossier client introuvable.' });
      }

      const existingData = docSnap.data() || {};
      const currentMensurations = existingData.mensurations || [];

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

      const updatedMensurations = [newEntry, ...currentMensurations.filter(Boolean)];

      await dossierRef.update({ mensurations: updatedMensurations });

      res.status(201).json({
        message: 'Mensuration ajoutée avec succès.',
        data: newEntry
      });

    } catch (err) {
      console.error(`💥 Erreur Firestore - ajout mensuration :`, err.message);
      res.status(500).json({ message: "Erreur serveur lors de l’ajout de mensuration." });
    }
  }
);

///////////////////////////////////////// ENTRAINEMENTS /////////////////////////////////////////////////////

// Route POST n°2 // Enregistrement d’un ou plusieurs entraînements pour un client
// 📥 Reçoit un email + tableau d’entrainements dans le corps de la requête
// 🆔 Génère un nouvel ID UUID pour chaque entraînement et performance créée
// 🏋️‍♂️ Gère les types d’entraînements classiques et cross-training (avec circuits)
// 🔄 Met à jour les listes entrainements et performances dans le dossier client
// ⚠️ Nécessite que le dossier client existe sinon renvoie 404
app.post('/RouteEnregistrementTraing', authenticateToken, async (req, res) => {
  console.log('📥 Body reçu:', req.body);
  try {
    const email = req.user.email.toLowerCase();
    const { entrainements } = req.body;

    // 🧪 Validation
    if (!Array.isArray(entrainements) || entrainements.length === 0) {
      return res.status(400).json({ error: 'Entraînement vide.' });
    }

    const sanitizedEmail = email.replace(/[@.]/g, '_');
    const dossierRef = db
      .collection('users')
      .doc(sanitizedEmail)
      .collection('dossier_client')
      .doc(sanitizedEmail);

    const docSnap = await dossierRef.get();

    if (!docSnap.exists) {
      console.warn(`❌ Utilisateur non trouvé : ${sanitizedEmail}`);
      return res.status(404).json({ error: 'Utilisateur non trouvé.' });
    }

    const clientData = docSnap.data() || {};
    const entrainementsActuels = clientData.entrainements || [];
    const performancesActuelles = clientData.performances || [];

    const nouveauxEntrainements = [];
    const nouvellesPerformances = [];

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

      const newId = uuidv4();

      if (typeTraining === 'cross-training') {
        const circuitsFormates = exercices.map((circuit) => ({
          nom: circuit.nom,
          tours: circuit.tours,
          on: circuit.on,
          off: circuit.off,
          exercices: circuit.exercices,
        }));

        nouveauxEntrainements.push({
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
        nouveauxEntrainements.push({
          id: newId,
          date,
          muscle1,
          muscle2,
          muscle3,
          typeTraining,
          exercices,
          noteTraining,
        });

        exercices.forEach((exo) => {
          const perfId = uuidv4();
          nouvellesPerformances.push({
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

    await dossierRef.update({
      entrainements: [...nouveauxEntrainements, ...entrainementsActuels],
      performances: [...nouvellesPerformances, ...performancesActuelles],
    });

    res.status(201).json({ message: 'Entraînement enregistré avec succès.' });

  } catch (err) {
    console.error("💥 Erreur Firestore RouteEnregistrementTraing:", err.message);
    res.status(500).json({ error: 'Erreur interne serveur.' });
  }
});

//////////////////////////////////////////// DIETE /////////////////////////////////////////////////////////

// Route POST n°3 // Création ou mise à jour d’une diète dans le dossier client
// 📥 Reçoit email, id (optionnel), date, diete (objet ou tableau), kcalObjectif, mode
// 🔄 Si id fourni, met à jour la diète existante, sinon crée une nouvelle avec un id timestamp
// ⚠️ Vérifie que le dossier client existe sinon renvoie 404
// 📝 Met à jour le fichier JSON du client avec la nouvelle liste de diètes
app.post('/CoachDieteGenerator', authenticateToken, async (req, res) => {
  try {
    const email = req.user.email.toLowerCase();
    const { id, date, diete, kcalObjectif, mode } = req.body;

    // 🛡️ Validation des données reçues
    if (!Array.isArray(diete) && typeof diete !== 'object') {
      return res.status(400).json({ error: 'Diète vide ou invalide.' });
    }

    const sanitizedEmail = email.replace(/[@.]/g, '_');
    const dossierRef = db
      .collection('users')
      .doc(sanitizedEmail)
      .collection('dossier_client')
      .doc(sanitizedEmail);

    const docSnap = await dossierRef.get();

    if (!docSnap.exists) {
      return res.status(404).json({ error: 'Utilisateur non trouvé.' });
    }

    const clientData = docSnap.data() || {};
    const dietes = Array.isArray(clientData.dietes) ? [...clientData.dietes] : [];

    if (id) {
      // 🔄 Mise à jour de la diète existante
      const index = dietes.findIndex(d => d.id === id);
      const updated = { id, date, kcalObjectif, repas: diete, mode };

      if (index !== -1) {
        dietes[index] = updated;
      } else {
        dietes.push(updated);
      }
    } else {
      // ➕ Ajout d’une nouvelle diète
      const newId = Date.now().toString();
      dietes.push({ id: newId, date, kcalObjectif, repas: diete, mode });
    }

    // 📥 Sauvegarde dans Firestore
    await dossierRef.update({ dietes });

    console.log('✅ Diète sauvegardée avec succès !');
    res.status(201).json({ message: 'Diète sauvegardée avec succès.' });

  } catch (err) {
    console.error('💥 Erreur Firestore CoachDieteGenerator:', err.message);
    res.status(500).json({ error: 'Erreur interne serveur.' });
  }
});

///////////////////////////////////////////// PERFORMANCES /////////////////////////////////////////////////////

// Route POST n°4 // Mise à jour des charges dans les performances d’un client
// 📥 Reçoit email et tableau d’updates { id, charges }
// 🔄 Pour chaque update, remplace les charges de la performance correspondante par les nouvelles valides
// ⚠️ Vérifie que le dossier client existe sinon renvoie 404
// 📝 Enregistre les modifications dans le fichier JSON du client
app.post('/SuiviPerformanceClient', authenticateToken, async (req, res) => {
  try {
    const email = req.user.email.toLowerCase();
    const { updates } = req.body;

    // 🧪 Vérification des données
    if (!Array.isArray(updates) || updates.length === 0) {
      return res.status(400).json({ error: 'Aucune mise à jour fournie.' });
    }

    const sanitizedEmail = email.replace(/[@.]/g, '_');
    const dossierRef = db
      .collection('users')
      .doc(sanitizedEmail)
      .collection('dossier_client')
      .doc(sanitizedEmail);

    const docSnap = await dossierRef.get();
    if (!docSnap.exists) {
      return res.status(404).json({ error: 'Utilisateur non trouvé.' });
    }

    const clientData = docSnap.data() || {};
    const performances = Array.isArray(clientData.performances) ? [...clientData.performances] : [];

    // 🔁 Mise à jour des performances
    updates.forEach(update => {
      const perf = performances.find(p => p.id === update.id);
      if (perf) {
        perf.charges = update.charges.filter(c =>
          c.date &&
          !isNaN(new Date(c.date)) &&
          c.charge !== undefined &&
          c.charge !== null &&
          c.charge !== ''
        );
        console.log(`✅ Charges mises à jour pour performance ID ${update.id}`);
      } else {
        console.warn(`⚠️ Performance non trouvée pour ID : ${update.id}`);
      }
    });

    // 💾 Sauvegarde
    await dossierRef.update({ performances });

    res.status(200).json({ message: 'Charges mises à jour avec succès.' });

  } catch (err) {
    console.error("💥 Erreur Firestore SuiviPerformanceClient:", err.message);
    res.status(500).json({ error: 'Erreur interne serveur.' });
  }
});

//////////////////////////////////////////// SUIVI CLIENT /////////////////////////////////////////////////////////
// Routes POST n°5 // 

// 📌 Initialiser la journée de suiviDiete si elle n'existe pas
app.post('/dossier/suividiete/init', authenticateToken, async (req, res) => {
  const email = req.user.email.toLowerCase();

  if (!email) return res.status(400).json({ error: 'Email requis.' });

  const sanitizedEmail = email.replace(/[@.]/g, '_');
  const dossierRef = db
    .collection('users')
    .doc(sanitizedEmail)
    .collection('dossier_client')
    .doc(sanitizedEmail);

  try {
    const docSnap = await dossierRef.get();

    if (!docSnap.exists) {
      return res.status(404).json({ error: 'Utilisateur non trouvé.' });
    }

    const clientData = docSnap.data() || {};
    const currentDate = new Date().toISOString().split('T')[0];

    // ⚙️ Création si la structure n’existe pas
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
      'avant_coucher'
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

    await dossierRef.update({
      suiviDiete: clientData.suiviDiete
    });

    return res.status(200).json({
      message: 'Journée ajoutée dans suiviDiete',
      date: currentDate,
      structure: nouveauJour
    });

  } catch (err) {
    console.error('💥 Erreur Firestore suiviDiete/init :', err.message);
    return res.status(500).json({ error: 'Erreur serveur Firestore.' });
  }
});


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// PUT METTRE A JOUR LES INFOS ///////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////// DIETE /////////////////////////////////////////////////////////

// Route PUT n°1 // Mise à jour d’une diète spécifique dans le dossier client
// 🔒 Protégée (idéalement à sécuriser avec un token)
// 🥗 Met à jour la diète identifiée par son ID dans le dossier JSON du client
// 🗃️ Modifie la date, repas, objectif kcal

app.put('/CoachDossierDiete', authenticateToken, async (req, res) => {
  try {
    const email = req.user.email.toLowerCase();
    const { id, date, diete, kcalObjectif } = req.body;

    // 🛡️ Validation
    if (!id) return res.status(400).json({ error: 'ID de la diète requis pour la mise à jour.' });
    if (!email) return res.status(400).json({ error: 'Email requis.' });
    if (!diete) return res.status(400).json({ error: 'Diète vide ou invalide.' });

    const sanitizedEmail = email.replace(/[@.]/g, '_');

    const dossierRef = db
      .collection('users')
      .doc(sanitizedEmail)
      .collection('dossier_client')
      .doc(sanitizedEmail);

    const docSnap = await dossierRef.get();

    if (!docSnap.exists) {
      return res.status(404).json({ error: 'Utilisateur non trouvé.' });
    }

    const clientData = docSnap.data() || {};
    const dietes = Array.isArray(clientData.dietes) ? clientData.dietes : [];

    const index = dietes.findIndex(d => d.id === id);

    if (index === -1) {
      return res.status(404).json({ error: 'Diète non trouvée pour cet ID.' });
    }

    // ✏️ Mise à jour
    dietes[index] = {
      id,
      date,
      repas: diete,
      kcalObjectif,
    };

    await dossierRef.update({ dietes });

    console.log("✅ Diète mise à jour avec succès !");
    return res.status(200).json({ message: 'Diète mise à jour avec succès.' });

  } catch (err) {
    console.error("💥 Erreur Firestore CoachDossierDiete:", err.message);
    return res.status(500).json({ error: 'Erreur interne Firestore.' });
  }
});

///////////////////////////////////////// ENTRAINEMENTS /////////////////////////////////////////////////////

// Route PUT n°2 // Mise à jour des entraînements d’un client
// 🏋️‍♂️ Remplace complètement la liste des entraînements dans le dossier client
// 📂 Le dossier client est identifié par l’email (nettoyé pour nom de fichier)
// 🔒 À sécuriser idéalement par un middleware d’authentification
app.put('/CoachDossierEntrainements', authenticateToken, async (req, res) => {
  const email = req.user.email;
  const { entrainements } = req.body;

  // 🔍 Validation des données
  if (!email || !Array.isArray(entrainements)) {
    return res.status(400).json({ error: 'Email ou entraînements invalides' });
  }

  const sanitizedEmail = email.toLowerCase().replace(/[@.]/g, '_');

  const dossierRef = db
    .collection('users')
    .doc(sanitizedEmail)
    .collection('dossier_client')
    .doc(sanitizedEmail);

  try {
    const docSnap = await dossierRef.get();

    if (!docSnap.exists) {
      return res.status(404).json({ error: "Fichier utilisateur introuvable" });
    }

    await dossierRef.update({ entrainements });

    return res.json({ message: 'Entraînements mis à jour avec succès' });
  } catch (error) {
    console.error("🔥 Erreur Firestore mise à jour entraînements :", error);
    return res.status(500).json({ error: "Erreur Firestore : " + error.message });
  }
});


///////////////////////////////////////////// PROFIL /////////////////////////////////////////////////////

// Route PUT n°3 // Mise à jour du profil, mensuration et objectifs d’un client
// 🔄 Modifie les premières entrées des tableaux profil, mensurationProfil et objectifs
// 🧾 Les données mises à jour sont extraites du corps de la requête (req.body)
// 📂 Le dossier client est identifié par l’email (sanitize pour le nom de fichier)
// ⚠️ Attention : la gestion des photos conserve l’ancienne si aucune nouvelle n’est fournie
// 🛑 À sécuriser idéalement avec un middleware d’authentification (ex : authenticateToken)
app.put('/dossier', authenticateToken, async (req, res) => {
  const email = req.user.email.toLowerCase();
  const sanitizedEmail = email.replace(/[@.]/g, '_');

  const dossierRef = db
    .collection('users')
    .doc(sanitizedEmail)
    .collection('dossier_client')
    .doc(sanitizedEmail);

  try {
    const docSnap = await dossierRef.get();

    if (!docSnap.exists) {
      return res.status(404).json({ message: 'Dossier non trouvé.' });
    }

    const dossier = docSnap.data();

    // ⚙️ Mise à jour des différentes sections du dossier
    const profil = {
      ...((dossier.profil && dossier.profil[0]) || {}),
      nom: req.body.nom,
      prenom: req.body.prenom,
      age: req.body.age,
      profession: req.body.profession,
      telephone: req.body.telephone,
      photoProfil: req.body.photoProfil || (dossier.profil?.[0]?.photoProfil ?? '')
    };

    const mensurationProfil = {
      ...((dossier.mensurationProfil && dossier.mensurationProfil[0]) || {}),
      taille: req.body.taille,
      poids: req.body.poids
    };

    const objectifs = {
      ...((dossier.objectifs && dossier.objectifs[0]) || {}),
      objectif: req.body.objectif
    };

    await dossierRef.update({
      profil: [profil],
      mensurationProfil: [mensurationProfil],
      objectifs: [objectifs]
    });

    res.json({ message: 'Profil mis à jour avec succès' });
  } catch (err) {
    console.error("🔥 Erreur Firestore mise à jour profil :", err);
    res.status(500).json({ message: 'Erreur serveur lors de la mise à jour.' });
  }
});

//////////////////////////////////////////////////////////////////////////////////////////////////////////
// Routes PUT n°4 // 
// ✅ Mise à jour d’un repas dans suiviDiete
app.put('/dossier/suividiete/:date/:repasType', authenticateToken, async (req, res) => {
  const email = req.user.email.toLowerCase();
  const sanitizedEmail = email.replace(/[@.]/g, '_');

  const { date, repasType } = req.params;
  const { aliments, commentaire } = req.body;

  if (!date || !repasType) {
    return res.status(400).json({ error: 'Paramètres manquants dans la requête.' });
  }

  const dossierRef = db
    .collection('users')
    .doc(sanitizedEmail)
    .collection('dossier_client')
    .doc(sanitizedEmail);

  try {
    const docSnap = await dossierRef.get();

    if (!docSnap.exists) {
      return res.status(404).json({ error: 'Utilisateur non trouvé.' });
    }

    const clientData = docSnap.data();

    if (!clientData.suiviDiete || !clientData.suiviDiete[date]) {
      return res.status(400).json({ error: 'Journée non initialisée.' });
    }

    const repasJour = clientData.suiviDiete[date];

    if (!repasJour[repasType]) {
      return res.status(400).json({ error: `Type de repas invalide : ${repasType}` });
    }

    // Mise à jour du repas
    repasJour[repasType] = {
      aliments: aliments || [],
      commentaire: commentaire || ''
    };

    await dossierRef.update({
      [`suiviDiete.${date}`]: repasJour
    });

    return res.status(200).json({ message: 'Repas mis à jour avec succès.' });
  } catch (err) {
    console.error("💥 Erreur Firestore lors de la mise à jour du repas :", err);
    return res.status(500).json({ error: 'Erreur serveur.' });
  }
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

