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
  credential: admin.credential.cert(serviceAccount),
    storageBucket: 'app-tf-coaching.firebasestorage.app',

});

const db = admin.firestore();
const bucket = admin.storage().bucket(); // ✅ C’est ça qu’il te manque
/////////////////////////////////////////////////////////////////////////////////////////////////////


// 🔧 Configs
const USERS_FILE = path.join(__dirname, 'users.json');
const dossiersPath = path.join(__dirname, 'data', 'dossiers');
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, 'uploads'));
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname); // ex: .jpg, .png
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + ext);
  }
});

const upload = multer({ storage });
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

//////////////////: Fire base Storage 
app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    const localFilePath = req.file.path;
    const destination = `photos-profil/${req.file.filename}`;

    await bucket.upload(localFilePath, {
      destination,
      public: true, // ou false selon si tu veux un lien direct ou non
      metadata: {
        cacheControl: 'public, max-age=31536000',
      },
    });

    const publicUrl = `https://storage.googleapis.com/${bucket.name}/${destination}`;
    res.json({ url: publicUrl });
  } catch (err) {
    console.error(err);
    res.status(500).send("Erreur lors de l'upload");
  }
});
/////////////////: Fire base Storage 

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

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////// GENERATION DES TOKENS ///////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * 🛡️ MIDDLEWARE : AUTHENTIFICATION PAR TOKEN JWT
 * 
 * Vérifie la présence et la validité d’un token JWT dans les headers `Authorization`.
 * Si valide → attache les infos utilisateur à `req.user` et appelle `next()`
 * Sinon → réponse 401 ou 403 selon le cas.
 */

// Middleware d’authentification JWT
function authenticateToken(req, res, next) {
  // 🔍 Récupération du header Authorization
  const authHeader = req.headers['authorization'];
  console.log("🧾 [auth] Authorization Header:", authHeader);

  // ✂️ Extraction du token depuis "Bearer <token>"
  const token = authHeader && authHeader.split(' ')[1];
  console.log("🔐 [auth] Token extrait :", token);

  // ❌ Aucun token trouvé → accès refusé
  if (!token) {
    console.log("❌ [auth] Aucun token fourni !");
    return res.sendStatus(401); // Unauthorized
  }

  // ✅ Vérification du token JWT
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      // ⏱️ Token expiré → réponse explicite
      if (err.name === 'TokenExpiredError') {
        console.log("❌ [auth] Token expiré !");
        return res.status(403).json({ message: 'Token expiré, veuillez vous reconnecter.' });
      }

      // ❌ Autre erreur → token invalide
      console.log("❌ [auth] Erreur vérification token :", err.message);
      return res.sendStatus(403); // Forbidden
    }

    console.log("✅ [auth] Token valide, utilisateur :", user);

    // 🚨 Vérification que la payload contient un ID utilisateur valide
    if (!user || (!user.uid && !user.id && !user.userId)) {
      console.log("❌ Payload JWT ne contient pas d'identifiant utilisateur valide");
      return res.status(401).json({ message: "Token invalide : pas d'identifiant utilisateur." });
    }

    req.user = user; // On attache la payload décodée à req.user
    next(); // 👣 Passage au middleware ou route suivant(e)
  });
}



//////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////// CONNEXION GENERAL ///////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * 🔐 ROUTE : AUTHENTIFICATION (LOGIN) UTILISATEUR
 * 
 * Cette route permet :
 * - La connexion d’un client (stocké en base)
 * - Une connexion spéciale "coach" avec un compte en dur
 * 
 * Retourne un token JWT pour les requêtes sécurisées par la suite.
 */
app.post('/login', async (req, res) => {
  let { email, password } = req.body;

  // Nettoyage de l'email
  email = email.trim().toLowerCase();

  // 🎯 Cas spécial : coach admin
  if (email === 'coach@admin.com' && password === 'coach123') {
    const token = jwt.sign(
      { email, role: 'coach', uid: 'coach_admin_com' },
      process.env.JWT_SECRET,
      { expiresIn: '3h' }
    );
    return res.json({ message: "Connexion coach réussie", token });
  }

  try {
    const usersRef = db.collection('users');
    const snapshot = await usersRef.where('email', '==', email).limit(1).get();

    // Si aucun utilisateur trouvé → email invalide
    if (snapshot.empty) {
      return res.status(401).json({
        error: 'email',
        message: "Adresse e-mail introuvable."
      });
    }

    const userDoc = snapshot.docs[0];
    const user = userDoc.data();

    // Vérification du mot de passe
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({
        error: 'password',
        message: "Mot de passe incorrect."
      });
    }

    // Connexion réussie
    const token = jwt.sign(
      {
        email: user.email,
        role: 'client',
        uid: userDoc.id
      },
      process.env.JWT_SECRET,
      { expiresIn: '3h' }
    );

    return res.json({ message: "Connexion réussie", token });

  } catch (error) {
    console.error("🔥 Erreur lors de la connexion :", error);
    return res.status(500).json({
      error: 'server',
      message: "Erreur serveur. Veuillez réessayer plus tard."
    });
  }
});

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////// AFFICHAGE UNIVERSEL (GET)///////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * 📂 ROUTE : RÉCUPÉRATION D'UN DOSSIER CLIENT
 * 
 * Cette route permet de récupérer un dossier client depuis Firestore.
 * - 🔐 Requiert un token JWT valide (coach ou client)
 * - 🔍 Si aucun `targetUserId` n’est précisé dans la query, l’utilisateur accède à son propre dossier
 * - 🛡️ Un client ne peut accéder qu’à SON propre dossier
 * - ✅ Un coach peut accéder à n’importe quel dossier
 */

app.get('/dossiers', authenticateToken, async (req, res) => {
  try {
    const requesterRole = req.user.role;
    const requesterId = req.user.uid || req.user.id || req.user.userId;

    if (!requesterRole || !requesterId) {
      return res.status(401).json({ message: "Utilisateur non authentifié." });
    }

    if (requesterRole === 'client') {
      // Client : on récupère juste SON dossier
      const dossierDoc = await db
        .collection('users')
        .doc(requesterId)
        .collection('dossier_client')
        .doc(requesterId)
        .get();

      if (!dossierDoc.exists) {
        return res.status(404).json({ message: "Dossier non trouvé." });
      }

      return res.json(dossierDoc.data());

    } else if (requesterRole === 'coach') {
      // Coach : on récupère tous les dossiers clients

      // Récupérer tous les users
      const usersSnapshot = await db.collection('users').get();

      // Pour chaque user, on récupère son dossier_client doc
      const dossiersPromises = usersSnapshot.docs.map(async userDoc => {
        const userId = userDoc.id;
        const dossierDoc = await db
          .collection('users')
          .doc(userId)
          .collection('dossier_client')
          .doc(userId)
          .get();

        if (dossierDoc.exists) {
          return { userId, dossier: dossierDoc.data() };
        }
        return null;
      });

      const dossiersResults = await Promise.all(dossiersPromises);
      const dossiers = dossiersResults.filter(d => d !== null);

      return res.json(dossiers);

    } else {
      return res.status(403).json({ message: "Rôle non autorisé." });
    }

  } catch (error) {
    console.error("Erreur récupération dossiers:", error);
    return res.status(500).json({ message: "Erreur serveur." });
  }
});





//////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// ENREGISTREMENT UNIVERSEL (POST) ///////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////



/**
 * 🚀 ROUTE GLOBALE : ENREGISTREMENT DOSSIER CLIENT (Nouveau client ou client connecté)
 * 
 * Cette route gère deux cas :
 * 1. 📦 Cas 1 : Création d’un nouveau client (sans authentification) → section === 'nouveauClient'
 * 2. 🔐 Cas 2 : Ajout/mise à jour de données client via les autres sections (requiert token JWT)
 */

app.post(
  '/dossier/enregistrer',
    upload.fields([
      { name: 'photoProfil', maxCount: 1 },
      { name: 'photoFace' },
      { name: 'photoDos' },
      { name: 'photoProfilD' },
      { name: 'photoProfilG' }
    ]),
    async (req, res) => {
    const { section, data } = req.body;
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
    /**
     * 📦 Cas 1 — Création d’un nouveau client (pas encore connecté)
     * Aucun token nécessaire ici.
     */

      if (section === 'nouveauClient') {
        try {
          const {
            email, password,
            securityQuestion, securityAnswer,
            profil, mensurationProfil, hygieneVie, objectifs,
            medical, physio, nutrition, activite, preference
          } = typeof data === 'string' ? JSON.parse(data) : data;

          if (!email || !password) {
            return res.status(400).json({ message: 'Email et mot de passe requis.' });
          }

          const emailToId = (email) => email.toLowerCase().replace(/[@.]/g, '_');
          const userId = emailToId(email);
          const userDocRef = db.collection('users').doc(userId);
          const userDoc = await userDocRef.get();

          if (userDoc.exists) {
            return res.status(409).json({ message: 'Utilisateur déjà existant.' });
          }

          const hashedPassword = bcrypt.hashSync(password, 10);

          await userDocRef.set({
            email,
            password: hashedPassword,
            security: {
              question: securityQuestion,
              answer: securityAnswer
            }
          });

          // Upload photoProfil sur Firebase Storage + récupérer URL publique
          if (req.files && req.files['photoProfil']) {
            const photoFile = req.files['photoProfil'][0];
            const destination = `photos_profil/${Date.now()}_${photoFile.originalname}`;
            await bucket.upload(photoFile.path, {
              destination,
              public: true,
              metadata: { contentType: photoFile.mimetype }
            });
            const publicUrl = `https://storage.googleapis.com/${bucket.name}/${destination}`;
            profil.photoProfil = publicUrl;
          }

          // Création du dossier client initial
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

          await userDocRef.collection('dossier_client').doc(userId).set(dossierClient);

          return res.status(201).json({ message: 'Utilisateur enregistré avec succès.', userId });
        } catch (error) {
          console.error("❌ Erreur inscription nouveau client :", error);
          return res.status(500).json({ message: "Erreur lors de l'inscription." });
        }
      }
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
    /**
     * ❓ Cas 1.5 — Vérification de la question de sécurité (sans authentification)
     */
    if (section === 'verifySecurityQuestion') {
      try {
        const { email } = typeof data === 'string' ? JSON.parse(data) : data;

        if (!email) {
          return res.status(400).json({ message: 'Email requis.' });
        }

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

        return res.json({ question: user.security.question });
      } catch (error) {
        console.error('❌ Erreur lors de la récupération de la question :', error);
        return res.status(500).json({ message: 'Erreur serveur.' });
      }
    }
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
    /**
     * 🔄 Cas 1.75 — Réinitialisation du mot de passe via question de sécurité (sans authentification)
     */
    if (section === 'resetPassword') {
      try {
        const { email, answer, newPassword } = typeof data === 'string' ? JSON.parse(data) : data;

        if (!email || !answer || !newPassword) {
          return res.status(400).json({ message: 'Champs manquants' });
        }

        const userId = email.toLowerCase().replace(/[@.]/g, '_');
        const userDocRef = db.collection('users').doc(userId);
        const userDoc = await userDocRef.get();

        if (!userDoc.exists) {
          return res.status(404).json({ message: 'Utilisateur introuvable.' });
        }

        const userData = userDoc.data();

        if (!userData.security || !userData.security.answer) {
          return res.status(400).json({ message: 'Aucune réponse de sécurité enregistrée.' });
        }

        if (userData.security.answer.toLowerCase() !== answer.toLowerCase()) {
          return res.status(403).json({ message: 'Réponse incorrecte.' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await userDocRef.update({ password: hashedPassword });

        return res.json({ message: 'Mot de passe mis à jour avec succès.' });
      } catch (error) {
        console.error('❌ Erreur lors du reset password :', error);
        return res.status(500).json({ message: "Erreur serveur lors de la mise à jour du mot de passe." });
      }
    }
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
    /**
     * 🔐 Cas 2 — Accès authentifié (client ou coach) pour les autres sections
     */
    authenticateToken(req, res, async () => {


      try {
        const userEmail = req.user.email.toLowerCase();
        const userId = userEmail.replace(/[@.]/g, '_');
        const dossierRef = db.collection('users').doc(userId).collection('dossier_client').doc(userId);

        if (!section || !data) {
          return res.status(400).json({ message: 'Section et data sont obligatoires.' });
        }

        const dossierSnap = await dossierRef.get();
        if (!dossierSnap.exists) {
          return res.status(404).json({ message: 'Dossier client introuvable.' });
        }

        const dossierData = dossierSnap.data();
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /**
         * SECTION: changement de mot de passe
         * 🔒 Permet à un utilisateur connecté de changer son mot de passe en vérifiant l'ancien
         */
         if (section === 'changePassword') {
          const { currentPassword, newPassword } = typeof data === 'string' ? JSON.parse(data) : data;

          if (!currentPassword || !newPassword) {
            return res.status(400).json({ message: 'Champs manquants' });
          }

          // Récupérer le userDoc
          const userDocRef = db.collection('users').doc(userId);
          const userDoc = await userDocRef.get();

          if (!userDoc.exists) {
            return res.status(404).json({ message: 'Utilisateur non trouvé.' });
          }

          const user = userDoc.data();

          // Vérifier le password actuel
          const validPassword = await bcrypt.compare(currentPassword, user.password);
          if (!validPassword) {
            return res.status(403).json({ message: 'Mot de passe actuel incorrect.' });
          }

          // Hasher et mettre à jour le mot de passe
          const hashedPassword = await bcrypt.hash(newPassword, 10);
          await userDocRef.update({ password: hashedPassword });

          return res.json({ message: 'Mot de passe changé avec succès.' });
        }

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /**
         * SECTION: mensurations
         * ➕ Ajoute une nouvelle entrée de mensurations avec upload de photos
         */
        if (section === 'mensurations') {
          try {
            const mensurationData = typeof data === 'string' ? JSON.parse(data) : data;

            // Fonction pour upload un fichier sur Firebase Storage
            async function uploadFileToFirebase(file, folder) {
              if (!file) return null;
              const destination = `${folder}/${Date.now()}_${file.originalname}`;
              await bucket.upload(file.path, {
                destination,
                public: true,
                metadata: { contentType: file.mimetype }
              });
              // Supprimer le fichier local après upload
              fs.unlink(file.path, (err) => {
                if (err) console.warn('Erreur suppression fichier local:', err);
              });
              return `https://storage.googleapis.com/${bucket.name}/${destination}`;
            }

            // Upload photos et récupérer URL
            const photoFaceUrl = await uploadFileToFirebase(req.files['photoFace'] ? req.files['photoFace'][0] : null, 'mensurations');
            const photoDosUrl = await uploadFileToFirebase(req.files['photoDos'] ? req.files['photoDos'][0] : null, 'mensurations');
            const photoProfilDUrl = await uploadFileToFirebase(req.files['photoProfilD'] ? req.files['photoProfilD'][0] : null, 'mensurations');
            const photoProfilGUrl = await uploadFileToFirebase(req.files['photoProfilG'] ? req.files['photoProfilG'][0] : null, 'mensurations');

            // Construire la nouvelle entrée mensuration avec URLs photos
            const newEntry = {
              id: uuidv4(),
              date: mensurationData.date || new Date().toISOString().split('T')[0],
              poids: mensurationData.poids || '',
              poitrine: mensurationData.poitrine || '',
              taille: mensurationData.taille || '',
              hanches: mensurationData.hanches || '',
              brasD: mensurationData.brasD || '',
              brasG: mensurationData.brasG || '',
              cuisseD: mensurationData.cuisseD || '',
              cuisseG: mensurationData.cuisseG || '',
              molletD: mensurationData.molletD || '',
              molletG: mensurationData.molletG || '',
              photoFace: photoFaceUrl,
              photoDos: photoDosUrl,
              photoProfilD: photoProfilDUrl,
              photoProfilG: photoProfilGUrl
            };

            const userEmail = req.user.email.toLowerCase();
            const userId = userEmail.replace(/[@.]/g, '_');
            const dossierId = userId;
            const dossierRef = db.collection('users').doc(userId).collection('dossier_client').doc(dossierId);

            const dossierSnap = await dossierRef.get();
            if (!dossierSnap.exists) {
              return res.status(404).json({ message: 'Dossier introuvable.' });
            }
            const dossierData = dossierSnap.data();

            const updatedMensurations = [newEntry, ...(dossierData.mensurations || []).filter(Boolean)];

            await dossierRef.update({ mensurations: updatedMensurations });

            return res.status(201).json({ message: 'Mensuration ajoutée.', data: newEntry });
          } catch (error) {
            console.error("❌ Erreur ajout mensuration :", error);
            return res.status(500).json({ message: "Erreur lors de l'ajout de mensuration." });
          }
        }
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /**
         * SECTION: entrainements
         * ➕ Ajoute des séances et génère les performances correspondantes
         */
        if (section === 'entrainements') {

            const programmes = typeof data === 'string' ? JSON.parse(data) : data;

            if (!Array.isArray(programmes) || programmes.length === 0) {
              return res.status(400).json({ message: 'Programmes invalides.' });
            }

            const entrainementsActuels = dossierData.entrainements || [];
            const performancesActuelles = dossierData.performances || [];

            const joursSemaine = ['lundi', 'mardi', 'mercredi', 'jeudi', 'vendredi', 'samedi', 'dimanche'];

            // 🗂️ Index des anciens programmes
            const programmesParNom = {};
            entrainementsActuels.forEach(p => {
              programmesParNom[p.nomProgramme] = p;
            });

            // 🆕 Traitement des nouveaux programmes
            programmes.forEach(prog => {
            const programmeId = prog.id || uuidv4();
            const nomProgramme = prog.nomProgramme || prog.nom || '';
            const typeTraining = prog.typeTraining || '';
            const objectifs = prog.objectif || '';
            const date = prog.date || '';


            if (!programmesParNom[nomProgramme]) {
              programmesParNom[nomProgramme] = {
                programmeId,
                date,
                nomProgramme,
                objectifs,
                jours: {}
              };
            }

            const cible = programmesParNom[nomProgramme];

            joursSemaine.forEach(jour => {
              const blocs = prog.jours?.[jour];
              if (!Array.isArray(blocs) || blocs.length === 0) return;

              if (!Array.isArray(cible.jours[jour])) {
                cible.jours[jour] = [];
              }

              blocs.forEach(bloc => {
                const exercices = bloc.exercices || [];

                if (!Array.isArray(exercices) || exercices.length === 0) return;

                const blocExiste = cible.jours[jour].some(existing =>
                  JSON.stringify(existing.exercices) === JSON.stringify(bloc.exercices)
                );

                if (!blocExiste) {
                  cible.jours[jour].push({
                    ...bloc, // on garde tout, y compris on/off/tours etc.
                    typeTraining: bloc.typeTraining || typeTraining || '',
                    muscle1: bloc.muscle1 || '',
                    muscle2: bloc.muscle2 || '',
                    muscle3: bloc.muscle3 || '',
                    ergoDebutFinActif: typeof bloc.ergoDebutFinActif === 'boolean' ? bloc.ergoDebutFinActif : true,
                    noteEntrainement: bloc.noteEntrainement || '',
                  });
                }
              });
            });
          });

          // 🧠 Génération des performances (hors cross-training & hors cardio)
          const nouvellesPerformances = [];

          Object.values(programmesParNom).forEach(prog => {
            Object.entries(prog.jours).forEach(([jour, blocs]) => {
              blocs.forEach(bloc => {
                const typeBloc = (bloc.typeTraining || prog.typeTraining || '').toLowerCase();

                // ⛔ Ignore les blocs non-muscu
                if (typeBloc === 'cross-training' || typeBloc === 'cardio') return;

                // ⛔ Ignore si format Tabata/EMOM/AMRAP
                if ('on' in bloc || 'off' in bloc || 'tours' in bloc) return;

                // ✅ Gestion des superSets et des exos simples
                const exosPourPerf = [];

                bloc.exercices.forEach(exo => {
                  if (exo.superSet && Array.isArray(exo.exercices)) {
                    exo.exercices.forEach(sub => {
                      if (sub.nom) exosPourPerf.push(sub);
                    });
                  } else if (exo.nom) {
                    exosPourPerf.push(exo);
                  }
                });

////////////////////
                if (exosPourPerf.length === 0) return;

                nouvellesPerformances.push({
                  id: uuidv4(),
                  jourS: jour,
                  programmeId: prog.programmeId,
                  nomProgramme: prog.nomProgramme,
                  typeTraining: typeBloc,
                  groupesMusculaires: [bloc.muscle1, bloc.muscle2, bloc.muscle3].filter(Boolean),
                  perfJour: exosPourPerf.map(exo => ({
                    id: exo.id || uuidv4(),
                    exercice: exo.nom,
                    typeExo: exo.type || 'musculation',
                    repetitions: parseInt(exo.repetitions) || 0,
                    series: parseInt(exo.series) || 0,
                    chargeList: [{
                      date: new Date().toISOString().split('T')[0],
                      charge: 0
                    }]
                  }))
                });
              });
            });
          });

          // Regroupement par programmeId
          const performancesRegroupees = nouvellesPerformances.reduce((acc, perf) => {
            if (!acc[perf.programmeId]) {
              acc[perf.programmeId] = {
                id: uuidv4(),
                programmeId: perf.programmeId,
                nomProgramme: perf.nomProgramme,
                perfProg: []
              };
            }

            acc[perf.programmeId].perfProg.push({
              id: perf.id,
              groupesMusculaires: perf.groupesMusculaires,
              typeTraining: perf.typeTraining,
              jourS: perf.jourS,
              perfJour: perf.perfJour
            });

            return acc;
          }, {});

          const performancesFinales = [...performancesActuelles];

          // Fusionner ou ajouter les nouvelles performances
          Object.values(performancesRegroupees).forEach(newPerf => {
            const existingIndex = performancesFinales.findIndex(
              perf => perf.programmeId === newPerf.programmeId
            );

            if (existingIndex !== -1) {
              // Fusionner perfProg par jour
              newPerf.perfProg.forEach(newJour => {
                const jourExisteDeja = performancesFinales[existingIndex].perfProg.some(
                  j => j.jourS === newJour.jourS
                );
              
                if (!jourExisteDeja) {
                  performancesFinales[existingIndex].perfProg.push(newJour);
                } else {
                  console.log(`⚠️ Jour "${newJour.jourS}" déjà présent pour ce programme, on ne le rajoute pas.`);
                }
              });
            } else {
              // Nouveau programmeId, on l’ajoute directement
              performancesFinales.push(newPerf);
            }
          });

          // 🔥 Mise à jour Firestore
          await dossierRef.update({
            entrainements: Object.values(programmesParNom),
            performances: [...performancesFinales, ...performancesActuelles]
          });

          return res.status(201).json({ message: 'Programmes enregistrés avec succès.' });
        }
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /**
         * SECTION: diete
         * 🔄 Ajoute ou met à jour une diète dans le dossier client
         */
        if (section === 'diete') {
          const { id, date, diete, kcalObjectif } = typeof data === 'string' ? JSON.parse(data) : data;

          // Validation simple
          if (!Array.isArray(diete) && typeof diete !== 'object') {
            return res.status(400).json({ message: 'Diète vide ou invalide.' });
          }

          const dietes = Array.isArray(dossierData.dietes) ? [...dossierData.dietes] : [];

          if (id) {
            // Mise à jour d’une diète existante
            const index = dietes.findIndex(d => d.id === id);
            const updated = { id, date, kcalObjectif, repas: diete };

            if (index !== -1) {
              dietes[index] = updated;
            } else {
              dietes.push(updated);
            }
          } else {
            // Ajout d’une nouvelle diète
            const newId = Date.now().toString();
            dietes.push({ id: newId, date, kcalObjectif, repas: diete });
          }

          // Sauvegarde dans Firestore
          await dossierRef.update({ dietes });

          return res.status(201).json({ message: 'Diète sauvegardée avec succès.' });
        }

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /**
         * SECTION SECTION pour initialiser une journée dans suiviDiete
         */
        if (section === 'suiviDieteInit') {
          const currentDate = new Date().toISOString().split('T')[0];

          if (!dossierData.suiviDiete) {
            dossierData.suiviDiete = {};
          }

          if (dossierData.suiviDiete[currentDate]) {
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
              aliments: [],
              repasValide: false,
              commentaire: ''
            };
          });

          dossierData.suiviDiete[currentDate] = nouveauJour;

          await dossierRef.update({
            suiviDiete: dossierData.suiviDiete
          });

          return res.status(200).json({
            message: 'Journée ajoutée dans suiviDiete',
            date: currentDate,
            structure: nouveauJour
          });
        }
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
        return res.status(400).json({ message: `Section inconnue: ${section}` });

      } catch (err) {
        console.error('Erreur route dossier/enregistrer :', err);
        return res.status(500).json({ message: 'Erreur serveur.' });
      }
    });
  }
);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////// MISE A JOUR UNIVERSEL (PUT) ///////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * 📝 ROUTE PUT /dossiers — MISE À JOUR DU DOSSIER CLIENT
 * 
 * Cette route permet à un utilisateur authentifié (client ou coach) de mettre à jour
 * plusieurs sections de son dossier client : profil, mensurations, objectifs, 
 * entrainements, dietes, performances.
 * 
 * Elle supporte l’upload d’une photo de profil (champ 'photoProfil') via multipart/form-data,
 * convertie en base64 pour stockage dans Firestore.
 * 
 * Chaque section envoyée (en JSON string via multipart) est parsée et fusionnée avec les données existantes.
 * 
 * En cas de succès, renvoie les sections mises à jour.
 * 
 * 🔐 Cette route est protégée par le middleware `authenticateToken`.
 */
app.put('/dossiers', authenticateToken, upload.single('photoProfil'), async (req, res) => {
  try {
    const email = req.user.email.toLowerCase();
    const sanitizedEmail = email.replace(/[@.]/g, '_');

    const dossierRef = db
      .collection('users')
      .doc(sanitizedEmail)
      .collection('dossier_client')
      .doc(sanitizedEmail);

    const docSnap = await dossierRef.get();
    if (!docSnap.exists) {
      return res.status(404).json({ message: 'Dossier non trouvé.' });
    }

    const dossier = docSnap.data() || {};
    const updatePayload = {};

    const sections = ['profil', 'mensurations', 'entrainements', 'dietes', 'performances', 'suiviDiete'];

    for (const section of sections) {
      if (req.body[section]) {
        let parsedData;
        if (typeof req.body[section] === 'string') {
          try {
            parsedData = JSON.parse(req.body[section]);
          } catch (e) {
            console.warn(`JSON invalide pour la section ${section}, on ignore cette section.`);
            continue;
          }
        } else if (typeof req.body[section] === 'object') {
          parsedData = req.body[section];
        } else {
          continue;
        }

        //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        if (section === 'profil') {
          const oldProfil = dossier.profil?.[0] || {};
          oldProfil.taille = oldProfil.taille != null ? oldProfil.taille.toString() : '';
          oldProfil.poids = oldProfil.poids != null ? oldProfil.poids.toString() : '';

          if (req.file) {
            // Upload dans Firebase Storage
            const destination = `photos_profil/${Date.now()}_${req.file.originalname}`;
            await bucket.upload(req.file.path, {
              destination,
              public: true,
              metadata: {
                contentType: req.file.mimetype,
              },
            });

            // Supprimer fichier local uploadé
            fs.unlink(req.file.path, (err) => {
              if (err) console.warn('Erreur suppression fichier local:', err);
            });

            // URL publique Firebase Storage
            const publicUrl = `https://storage.googleapis.com/${bucket.name}/${destination}`;

            // Met à jour la photoProfil dans les données à sauvegarder
            parsedData.photoProfil = publicUrl;
          }

          updatePayload.profil = [{ ...oldProfil, ...parsedData }];
        }
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        else if (section === 'entrainements') {
          if (Array.isArray(parsedData)) {

            updatePayload.entrainements = parsedData.map(programme => {
              const { groupesMusculaires, ...cleanProgramme } = programme;
              return cleanProgramme;
            });
        
            const performancesActuelles = dossier.performances || [];
            const performancesMAJ = [...performancesActuelles]; // Copie pour édition
        
            parsedData.forEach(programme => {
              const programmeId = programme.programmeId || programme.id;
              const performanceExistante = performancesMAJ.find(p => p.programmeId === programmeId);
        
              if (!performanceExistante) return;
        
              // Copie profonde des performances existantes pour modification
              const perfProgActuel = performanceExistante.perfProg ? [...performanceExistante.perfProg] : [];
        
              Object.entries(programme.jours || {}).forEach(([jour, blocs]) => {
                blocs.forEach(bloc => {
                  const typeBloc = (bloc.typeTraining || programme.typeTraining || '').toLowerCase();
        
                  if (typeBloc === 'cross-training' || typeBloc === 'cardio') return;
                  if ('on' in bloc || 'off' in bloc || 'tours' in bloc) return;
        
                  const nouveauxExos = [];
        
                  bloc.exercices.forEach(exo => {
                    const processExo = (e) => {
                      if (!e.nom) return;
        
                      const exoId = e.id || uuidv4();
        
                      const exoExistant = perfProgActuel
                        .flatMap(p => p.perfJour)
                        .find(pe => pe.id === exoId);
        
                      const chargeList = exoExistant?.chargeList || [{
                        date: new Date().toISOString().split('T')[0],
                        charge: 0
                      }];
        
                      nouveauxExos.push({
                        id: exoId,
                        exercice: e.nom,
                        typeExo: e.type || 'musculation',
                        repetitions: parseInt(e.repetitions) || 0,
                        series: parseInt(e.series) || 0,
                        chargeList,
                        typeTraining: typeBloc,
                      });
                    };
        
                    if (exo.superSet && Array.isArray(exo.exercices)) {
                      exo.exercices.forEach(processExo);
                    } else {
                      processExo(exo);
                    }
                  });
        
                  if (nouveauxExos.length === 0) return;
        
                  // Recherche d’un bloc existant avec même jour + typeTraining
                  const blocExistant = perfProgActuel.find(p =>
                    p.jourS === jour &&
                    p.typeTraining === typeBloc &&
                    JSON.stringify(p.groupesMusculaires.sort()) === JSON.stringify([bloc.muscle1, bloc.muscle2, bloc.muscle3].filter(Boolean).sort())
                  );
        
                  if (blocExistant) {
                    nouveauxExos.forEach(nouveau => {
                      const indexExistant = blocExistant.perfJour.findIndex(e => e.id === nouveau.id);
                    
                      if (indexExistant === -1) {
                        // L'exo n'existait pas, on l'ajoute
                        blocExistant.perfJour.push(nouveau);
                      } else {
                        const exoActuel = blocExistant.perfJour[indexExistant];
                    
                        // Mise à jour uniquement si les données ont changé
                        const updatedExo = {
                          ...exoActuel,
                          exercice: nouveau.exercice,
                          typeExo: nouveau.typeExo,
                          repetitions: nouveau.repetitions,
                          series: nouveau.series,
                          // on garde chargeList existant sauf si tu veux l'écraser aussi
                        };
                    
                        blocExistant.perfJour[indexExistant] = updatedExo;
                      }
                    });
                  } else {
                    perfProgActuel.push({
                      id: uuidv4(),
                      groupesMusculaires: [bloc.muscle1, bloc.muscle2, bloc.muscle3].filter(Boolean),
                      typeTraining: typeBloc,
                      jourS: jour,
                      perfJour: nouveauxExos
                    });
                  }
                });
              });
        
              // Mise à jour des performances fusionnées dans la structure finale
              const index = performancesMAJ.findIndex(p => p.programmeId === programmeId);
              if (index !== -1) {
                performancesMAJ[index] = {
                  ...performanceExistante,
                  nomProgramme: programme.nomProgramme || programme.nom,
                  typeTraining: programme.typeTraining || '',
                  perfProg: perfProgActuel
                };
              }
            });
        
            updatePayload.performances = performancesMAJ;
          } else {
            console.warn('Entrainements attendus sous forme de tableau.');
          }
        }
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////

        else if (section === 'performances') {
          const performancesActuelles = dossier.performances || [];

          const performancesModifiees = parsedData; // attendu: tableau avec programmeId, jourS, perfJour[]

          const updatedPerformances = performancesActuelles.map(prog => {
            const modifCorrespondante = performancesModifiees.find(m => m.programmeId === prog.programmeId);
            if (!modifCorrespondante) return prog;

            const updatedPerfMap = new Map(
              (modifCorrespondante.perfProg || []).map(p => [p.id, p])
            );

            const perfProgUpdated = (prog.perfProg || []).map(jourPerf => {
              if (jourPerf.jourS !== modifCorrespondante.jourS) return jourPerf;

              const newData = updatedPerfMap.get(jourPerf.id);
              if (!newData) return jourPerf;

              const updatedPerfJour = (jourPerf.perfJour || []).map(exo => {
                const updatedExo = (newData.perfJour || []).find(e => e.id === exo.id);
                return updatedExo ? { ...exo, chargeList: updatedExo.chargeList } : exo;
              });

              return {
                ...jourPerf,
                perfJour: updatedPerfJour
              };
            });

            return {
              ...prog,
              perfProg: perfProgUpdated
            };
          });

          updatePayload.performances = updatedPerformances;
        }

        //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        else if (section === 'dietes') {
          if (!Array.isArray(dossier.dietes)) {
            dossier.dietes = dossier.dietes ? [dossier.dietes] : [];
          }

          if (Array.isArray(dossier.dietes)) {
            if (Array.isArray(parsedData)) {
              updatePayload.dietes = parsedData;
              console.log('✏️ Remplacement complet de dietes');
            } else if (parsedData.id) {
              const dietes = [...dossier.dietes];
              const index = dietes.findIndex(d => d.id === parsedData.id);
              if (index !== -1) {
                dietes[index] = { ...dietes[index], ...parsedData };
                updatePayload.dietes = dietes;
                console.log(`✏️ Mise à jour diète id=${parsedData.id}`);
              } else {
                console.warn(`⚠️ Diète avec id ${parsedData.id} non trouvée.`);
              }
            } else {
              console.warn('⚠️ Aucune id trouvée pour mise à jour diète.');
            }
          } else {
            console.warn('⚠️ Aucune liste de dietes existante.');
          }
        }

        //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        else if (section === 'suiviDiete') {
          const oldSuivi = dossier.suiviDiete || {};

          for (const dateKey in parsedData) {
            const repasData = parsedData[dateKey];

            if (!oldSuivi[dateKey]) {
              return res.status(400).json({ error: `Journée ${dateKey} non initialisée.` });
            }

            for (const repasType in repasData) {
              const repas = repasData[repasType];

              if (!oldSuivi[dateKey][repasType]) {
                return res.status(400).json({ error: `Type de repas invalide : ${repasType}` });
              }

              oldSuivi[dateKey][repasType] = {
                aliments: repas.aliments || [],
                commentaire: repas.commentaire || '',
                repasValide: repas.repasValide === true
              };
            }
          }

          updatePayload.suiviDiete = oldSuivi;
        }

        //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } // <-- Fin du `if (req.body[section])`
    } // <-- Fin du `for (const section of sections)`

    if (Object.keys(updatePayload).length === 0) {
      return res.status(400).json({ message: 'Aucune donnée valide reçue pour mise à jour.' });
    }

    await dossierRef.update(updatePayload);

    res.json({ message: 'Dossier mis à jour avec succès', updatedSections: Object.keys(updatePayload) });

  } catch (err) {
    console.error("🔥 Erreur Firestore mise à jour dossier :", err);
    res.status(500).json({ message: 'Erreur serveur lors de la mise à jour.' });
  }
}); // <-- Fin de app.put

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////// ROUTES DELETE ///////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * 🗑️ Route DELETE /dossiers/supprimer
 * 
 * Permet de supprimer un élément spécifique d'une section du dossier client (ex: mensurations, diètes, entraînements).
 * L'utilisateur doit être authentifié. Seules certaines sections sont autorisées à la suppression.
 * 
 * 🔒 Authentification requise (token JWT)
 * 📦 Body attendu :
 *    - section : nom de la section (ex: "dietes", "mensurations")
 *    - id      : identifiant unique de l’élément à supprimer
 * 
 * ✅ Exemples de sections gérées : mensurations, dietes, entrainements
 * 🔁 Extensible facilement en ajoutant des sections dans la liste autorisée
 * 
 * 🕵️‍♂️ Vérifie que le document existe avant de tenter une suppression
 */
app.delete('/dossiers/supprimer', authenticateToken, async (req, res) => {
  console.log('🛑 DELETE /dossiers/supprimer appelé');
  console.log('User:', req.user.email);
  console.log('Body:', req.body);

  try {
    const email = req.user.email.toLowerCase();
    const sanitizedEmail = email.replace(/[@.]/g, '_');

    const { section, id } = req.body;

    console.log(`Section demandée: ${section}, id: ${id}`);

    if (!section || !id) {
      console.log('⚠️ Section ou ID manquants');
      return res.status(400).json({ message: 'Section et ID sont requis.' });
    }

    const sectionsAutorisees = ['mensurations', 'dietes', 'entrainements'];
    if (!sectionsAutorisees.includes(section)) {
      console.log(`⚠️ Section ${section} non autorisée`);
      return res.status(400).json({ message: `Section ${section} non gérée.` });
    }

    const dossierRef = db
      .collection('users')
      .doc(sanitizedEmail)
      .collection('dossier_client')
      .doc(sanitizedEmail);

    const docSnap = await dossierRef.get();

    if (!docSnap.exists) {
      console.log('⚠️ Dossier non trouvé');
      return res.status(404).json({ message: 'Dossier non trouvé.' });
    }

    const dossier = docSnap.data() || {};
    const sectionData = dossier[section];

    if (!Array.isArray(sectionData)) {
      console.log(`⚠️ La section ${section} n'est pas un tableau`);
      return res.status(400).json({ message: `La section ${section} n'est pas un tableau.` });
    }

    const newSectionData = sectionData.filter(item => item.id !== id && item._id !== id);

    if (newSectionData.length === sectionData.length) {
      console.log(`⚠️ Élément avec l'ID ${id} non trouvé dans ${section}`);
      return res.status(404).json({ message: `Élément avec l'ID ${id} non trouvé dans ${section}.` });
    }

    const updatePayload = { [section]: newSectionData };

    await dossierRef.update(updatePayload);

    console.log(`✅ Élément supprimé avec succès de la section ${section}`);
    res.status(200).json({ message: `Élément supprimé avec succès de la section ${section}.` });

  } catch (err) {
    console.error("🔥 Erreur Firestore suppression :", err);
    res.status(500).json({ message: 'Erreur serveur lors de la suppression.' });
  }
});

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////// ROUTES SPECIFIQUE ///////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * 🔑 Route POST /api/generate-client-token
 * 
 * Génère un token JWT temporaire au nom d’un client, uniquement accessible aux utilisateurs
 * authentifiés avec le rôle "coach". Ce token permet au coach d’agir ou de se connecter
 * en tant que client pendant une durée limitée (45 minutes).
 */
// Route protégée : seul un coach connecté peut générer un token pour un client
app.post('/api/generate-client-token', authenticateToken, async (req, res) => {
  console.log("🔐 [POST] /api/generate-client-token appelée");

  try {
    // Étape 1 — Vérification rôle utilisateur
    const requestingUser = req.user;
    console.log("👤 Utilisateur connecté :", requestingUser);

    if (requestingUser.role !== 'coach') {
      console.log("⛔ Rôle invalide :", requestingUser.role);
      return res.status(403).json({ message: '⛔ Accès refusé : rôle coach requis.' });
    }

    // Étape 2 — Lecture des données envoyées
    const { clientId, password } = req.body;
    console.log("📥 Données reçues :", { clientId, password: '********' });

    if (!clientId || !password) {
      console.log("⚠️ Données manquantes !");
      return res.status(400).json({ message: '⚠️ clientId et password requis.' });
    }

    // Étape 3 — Récupération du coach depuis Firestore
    const coachId = requestingUser.uid;
    console.log("🔎 Recherche du coach avec l’ID :", coachId);

    const coachDoc = await db.collection('users').doc(coachId).get();

    if (!coachDoc.exists) {
      console.log(`❌ Aucun document trouvé pour coachId ${coachId}`);
      return res.status(404).json({ message: '❌ Coach introuvable.' });
    }

    const coachData = coachDoc.data();
    console.log("✅ Coach trouvé :", coachData.email);

    // Étape 4 — Vérification mot de passe
    const isPasswordValid = await bcrypt.compare(password, coachData.password);
    if (!isPasswordValid) {
      console.log("🔐 Mot de passe incorrect !");
      return res.status(401).json({ message: '🔐 Mot de passe incorrect.' });
    }

    // Étape 5 — Vérification du client
    const clientDoc = await db.collection('users').doc(clientId).get();
    if (!clientDoc.exists) {
      console.log(`❌ Client avec ID ${clientId} introuvable.`);
      return res.status(404).json({ message: '❌ Client non trouvé.' });
    }

    const clientData = clientDoc.data();

    // Étape 6 — Génération du token
    const tokenClient = jwt.sign({
      uid: clientId,
      email: clientData.email,
      role: 'client'
    }, process.env.JWT_SECRET || 'secret123', { expiresIn: '3h' });

    console.log(`✅ Token client généré avec succès pour ${clientId}`);

    return res.json({ tokenClient });

  } catch (error) {
    console.error("❌ Erreur dans /generate-client-token :", error);
    return res.status(500).json({ message: 'Erreur serveur interne.' });
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


//////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////// FIN DE TOUTES LES ROUTES //////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////
