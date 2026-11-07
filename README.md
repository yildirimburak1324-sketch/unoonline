# UNO Online – Google & Discord girişi

## Kurulum
1. Node.js 18+ kur.
2. `npm install`
3. `.env.example` dosyasını `.env` olarak kopyala ve doldur.
4. `blue.jpg` ve `red.jpg` dosyalarını `public/` klasörüne koy.
5. `npm start` → http://localhost:3000

## Google anahtarı
console.cloud.google.com → APIs & Services → Credentials → Create OAuth client ID (Web application)
- Authorized redirect URI: `http://localhost:3000/auth/google/callback` (yayında kendi alan adın)
- Client ID / Secret → `.env`

## Discord anahtarı
discord.com/developers/applications → New Application → OAuth2
- Redirects: `http://localhost:3000/auth/discord/callback`
- Client ID / Secret → `.env`

Veritabanı: `uno.db` (SQLite), ilk çalıştırmada otomatik oluşur.

## Admin paneli
`http://localhost:3000/adminpanel` — giriş bilgileri `.env` içindeki `ADMIN_USER` / `ADMIN_PASS`
(`.env` yoksa varsayılan: zetastore / zetastore123**A). Yayına almadan önce şifreyi değiştir.

Google girişi şimdilik kapalı. Açmak için `.env` içine `GOOGLE_ENABLED=true` yaz.
