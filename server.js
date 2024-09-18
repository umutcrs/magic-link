const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const dotenv = require('dotenv');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, query, validationResult } = require('express-validator');
const winston = require('winston');
const expressWinston = require('express-winston');
const xss = require('xss');

dotenv.config();

const app = express();

// Logger yapılandırması
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'combined.log' })
  ],
});

// Express Winston Logger Middleware
app.use(expressWinston.logger({
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'requests.log' })
  ],
  format: winston.format.combine(
    winston.format.json(),
    winston.format.prettyPrint()
  ),
}));

// Güvenlik başlıkları
app.use(helmet());

// JSON body parser
app.use(express.json({ limit: '10kb' })); // Request body boyutunu sınırla

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 dakika
  max: 100 // IP başına 100 istek
});
app.use(limiter);

// MongoDB bağlantısı
const connectToMongoDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    logger.info('MongoDB bağlantısı başarılı');
  } catch (err) {
    logger.error('MongoDB bağlantı hatası:', err);
    process.exit(1);
  }
};

// Kullanıcı şeması
const userSchema = new mongoose.Schema({
  email: { 
    type: String, 
    required: true, 
    unique: true,
    lowercase: true,
    trim: true
  },
  magicLinkToken: String,
  tokenExpires: Date,
  loginAttempts: { type: Number, required: true, default: 0 },
  lockUntil: Date
});

userSchema.methods.incrementLoginAttempts = function(callback) {
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $set: { loginAttempts: 1 },
      $unset: { lockUntil: 1 }
    }, callback);
  }
  var updates = { $inc: { loginAttempts: 1 } };
  if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 }; // 2 saat kilit
  }
  return this.updateOne(updates, callback);
};

userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

const User = mongoose.model('User', userSchema);

// E-posta gönderici ayarları
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USERNAME,
    pass: process.env.GMAIL_PASSWORD,
  },
});

// Varsayılan şirket adını tanımlayalım
const DEFAULT_COMPANY_NAME = "SecurityTeam";

// Yeni e-posta içeriği oluşturma fonksiyonu
const createEmailContent = (magicLink, companyName = DEFAULT_COMPANY_NAME) => {
  const htmlContent = `
<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <title>Güvenli Giriş</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
  <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    <h1 style="color: #444444;">${companyName}</h1>
    <p>Merhaba,</p>
    <p>Hesabınıza güvenli giriş yapmanız için özel bir bağlantı oluşturduk. Aşağıdaki bağlantıya tıklayarak giriş yapabilirsiniz:</p>
    <p><a href="${magicLink}" style="display: inline-block; padding: 10px 20px; font-size: 16px; color: #ffffff; background-color: #007bff; text-decoration: none;">Güvenli Giriş Yap</a></p>
    <p>Bu bağlantı 15 dakika boyunca geçerlidir ve yalnızca bir kez kullanılabilir.</p>
    <p>Güvenliğiniz için: Giriş yapmadan önce adres çubuğundaki URL'in "${companyName.toLowerCase().replace(/\s+/g, '')}.com" ile başladığından emin olun.</p>
    <p>© ${new Date().getFullYear()} ${companyName}. Tüm hakları saklıdır.</p>
  </div>
</body>
</html>
  `;

  const textContent = `
Güvenli Giriş - ${companyName}

Merhaba,

Hesabınıza güvenli giriş yapmanız için özel bir bağlantı oluşturduk. Aşağıdaki bağlantıyı kullanarak giriş yapabilirsiniz:

${magicLink}

Bu bağlantı 15 dakika boyunca geçerlidir ve yalnızca bir kez kullanılabilir.

Güvenliğiniz için: Giriş yapmadan önce adres çubuğundaki URL'in "${companyName.toLowerCase().replace(/\s+/g, '')}.com" ile başladığından emin olun.

© ${new Date().getFullYear()} ${companyName}. Tüm hakları saklıdır.
  `;

  return { htmlContent, textContent };
};

// Güncellenmiş e-posta gönderme fonksiyonu
const sendEmail = async (to, subject, magicLink, companyName = DEFAULT_COMPANY_NAME) => {
  try {
    const { htmlContent, textContent } = createEmailContent(magicLink, companyName);
    await transporter.sendMail({ 
      to: xss(to), 
      subject: xss(subject), 
      html: htmlContent,
      text: textContent
    });
    logger.info(`E-posta gönderildi: ${xss(to)}`);
  } catch (err) {
    logger.error('E-posta gönderim hatası:', err);
    throw err;
  }
};

// Güçlü token oluşturma fonksiyonu
const createSecureToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Magic Link oluşturma fonksiyonu
const createMagicLink = (userId, token) => {
  const payload = `${userId}:${token}`;
  const encodedPayload = Buffer.from(payload).toString('base64');
  return `${process.env.APP_URL}/verify?token=${encodeURIComponent(encodedPayload)}`;
};

// Test e-postası gönderimi
const sendInitialEmail = async () => {
  try {
    const testEmail = 'umut-cara@hotmail.com';
    let user = await User.findOne({ email: testEmail });
    
    if (!user) {
      user = new User({ email: testEmail });
    }

    const token = createSecureToken();
    const hashedToken = await bcrypt.hash(token, 10);
    
    user.magicLinkToken = hashedToken;
    user.tokenExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 dakika geçerlilik süresi
    await user.save();

    const magicLink = createMagicLink(user._id, token);
    await sendEmail(testEmail, 'Test Giriş Linki', magicLink);
    logger.info('Test e-postası gönderildi!');
  } catch (err) {
    logger.error('Test e-postası gönderim hatası:', err);
  }
};

// Magic Link için endpoint
app.post('/request-magic-link', [
  body('email')
    .isEmail().withMessage('Geçerli bir e-posta adresi girin.')
    .normalizeEmail()
    .customSanitizer(value => xss(value))
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email } = req.body;

  try {
    let user = await User.findOne({ email });
    if (!user) {
      user = new User({ email });
    }

    if (user.isLocked) {
      return res.status(400).send('Hesap kilitli. Lütfen daha sonra tekrar deneyin.');
    }

    const token = createSecureToken();
    const hashedToken = await bcrypt.hash(token, 10);
    
    user.magicLinkToken = hashedToken;
    user.tokenExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 dakika geçerlilik süresi
    await user.save();

    const magicLink = createMagicLink(user._id, token);
    await sendEmail(email, 'Giriş Linki', magicLink);

    res.send('Magic link gönderildi!');
  } catch (err) {
    logger.error('Magic link oluşturma hatası:', err);
    res.status(500).send('Bir hata oluştu.');
  }
});

// Magic Link ile kimlik doğrulama endpointi
app.get('/verify', [
  query('token').trim().escape()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const encodedToken = req.query.token;
  
  try {
    const decodedPayload = Buffer.from(encodedToken, 'base64').toString('utf-8');
    const [userId, token] = decodedPayload.split(':');

    const user = await User.findOne({
      _id: userId,
      tokenExpires: { $gt: new Date() }
    });

    if (!user) {
      return res.status(400).send('Geçersiz veya süresi dolmuş link.');
    }

    const isValid = await bcrypt.compare(token, user.magicLinkToken);

    if (!isValid) {
      await user.incrementLoginAttempts();
      return res.status(400).send('Geçersiz token.');
    }

    // Token geçerli ve süresi dolmamışsa, kullanıcıyı güncelle
    user.magicLinkToken = null;
    user.tokenExpires = null;
    user.loginAttempts = 0;
    user.lockUntil = null;
    await user.save();

    res.send('Giriş başarılı!');
  } catch (err) {
    logger.error('Token doğrulama hatası:', err);
    res.status(400).send('Geçersiz token.');
  }
});

// Statik dosyalar için yönlendirme
app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Sunucu başlatma ve MongoDB'ye bağlanma
const PORT = process.env.PORT || 3001;
const startServer = async () => {
  try {
    await connectToMongoDB();
    const server = app.listen(PORT, async () => {
      logger.info(`Server is running on port ${PORT}`);
      await sendInitialEmail();
    });

    // Graceful shutdown
    process.on('SIGTERM', () => {
      logger.info('SIGTERM signal received: closing HTTP server');
      server.close(() => {
        logger.info('HTTP server closed');
        mongoose.connection.close(false, () => {
          logger.info('MongoDB connection closed');
          process.exit(0);
        });
      });
    });

  } catch (err) {
    logger.error('Server başlatma hatası:', err);
    process.exit(1);
  }
};

startServer();