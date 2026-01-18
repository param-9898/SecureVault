# 🚀 Deployment Guide - Free Hosting

This guide will help you deploy SecureVaultX for free so anyone with the link can use it.

## Overview

We'll deploy:
- **Backend (Flask API)** → Render.com (free tier)
- **Frontend (HTML/CSS/JS)** → Netlify (free tier)

**Estimated time:** 10-15 minutes

---

## Prerequisites

1. **GitHub Account** - [Create one here](https://github.com/join)
2. **Git installed** - [Download here](https://git-scm.com/downloads)

---

## Step 1: Push Code to GitHub

### 1.1 Create a new GitHub repository

1. Go to [github.com/new](https://github.com/new)
2. Name it: `SecureVaultX`
3. Set to **Public** (required for free hosting)
4. **Don't** initialize with README (we already have one)
5. Click **Create repository**

### 1.2 Push your code

Open terminal in your project folder and run:

```bash
cd e:\Download\SecureVaultX\SecureVaultX

# Initialize git (if not already)
git init

# Add all files
git add .

# Commit
git commit -m "Initial commit - SecureVaultX Web App"

# Add remote (replace YOUR_USERNAME with your GitHub username)
git remote add origin https://github.com/YOUR_USERNAME/SecureVaultX.git

# Push
git branch -M main
git push -u origin main
```

---

## Step 2: Deploy Backend to Render.com

### 2.1 Create Render account

1. Go to [render.com](https://render.com)
2. Click **Get Started for Free**
3. Sign up with GitHub (recommended)

### 2.2 Deploy the backend

1. Go to [Render Dashboard](https://dashboard.render.com)
2. Click **New +** → **Web Service**
3. Connect your GitHub repository
4. Configure:
   - **Name:** `securevaultx-api`
   - **Region:** Choose closest to you
   - **Branch:** `main`
   - **Root Directory:** `web/backend`
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app --bind 0.0.0.0:$PORT`
5. Click **Create Web Service**

### 2.3 Wait for deployment

- Takes 2-5 minutes for first deploy
- You'll get a URL like: `https://securevaultx-api.onrender.com`
- **Copy this URL!** You'll need it for the frontend

### 2.4 Test the backend

Visit: `https://YOUR-RENDER-URL.onrender.com/api/health`

You should see:
```json
{"status": "healthy", "version": "1.0.0", ...}
```

---

## Step 3: Update Frontend Configuration

### 3.1 Edit config.js

Open `web/frontend/js/config.js` and update the URL:

```javascript
// Replace with YOUR actual Render backend URL
window.API_BASE_URL = 'https://securevaultx-api.onrender.com/api';
```

### 3.2 Commit and push the change

```bash
git add web/frontend/js/config.js
git commit -m "Update API URL for production"
git push
```

---

## Step 4: Deploy Frontend to Netlify

### 4.1 Create Netlify account

1. Go to [netlify.com](https://netlify.com)
2. Click **Sign up**
3. Sign up with GitHub (recommended)

### 4.2 Deploy the frontend

**Option A: Drag and Drop (Easiest)**

1. Go to [Netlify Drop](https://app.netlify.com/drop)
2. Drag the `web/frontend` folder onto the page
3. Done! You'll get a URL immediately

**Option B: GitHub Integration (Auto-updates)**

1. Go to [Netlify Dashboard](https://app.netlify.com)
2. Click **Add new site** → **Import an existing project**
3. Choose **GitHub**
4. Select your `SecureVaultX` repository
5. Configure:
   - **Base directory:** `web/frontend`
   - **Build command:** (leave empty)
   - **Publish directory:** `web/frontend`
6. Click **Deploy site**

### 4.3 Get your site URL

After deployment, you'll get a URL like:
```
https://random-name-12345.netlify.app
```

You can customize this in **Site settings** → **Change site name**

---

## Step 5: Test Your Deployed App

1. Open your Netlify URL in a browser
2. Create a new account
3. Test encryption/decryption
4. Share the link with anyone!

---

## 🎉 Congratulations!

Your SecureVaultX is now live! Share your Netlify URL with anyone.

---

## Free Tier Limits

### Render.com (Backend)
- ✅ 750 hours/month free
- ⚠️ Sleeps after 15 min inactivity (wakes in ~30 seconds)
- ✅ Auto-deploy on git push

### Netlify (Frontend)
- ✅ 100GB bandwidth/month
- ✅ Unlimited sites
- ✅ Auto-deploy on git push
- ✅ Free SSL/HTTPS

---

## Troubleshooting

### Backend won't start?
- Check Render logs for errors
- Ensure `requirements.txt` is in `web/backend/`
- Verify Python version is 3.10+

### Frontend shows "Cannot connect to server"?
- Verify `config.js` has correct backend URL
- Wait 30 seconds for Render to wake up
- Check browser console for CORS errors

### CORS errors?
The backend already has CORS enabled. If issues persist:
1. Check the backend URL in `config.js` ends with `/api`
2. Don't include trailing slash

---

## Custom Domain (Optional)

Both Render and Netlify support custom domains on free tier:

1. Buy a domain (e.g., from Namecheap, ~$10/year)
2. Add it in Netlify: **Site settings** → **Domain management**
3. Update DNS records as instructed
4. Free SSL certificate is auto-provisioned

---

## Need Help?

- [Render Documentation](https://render.com/docs)
- [Netlify Documentation](https://docs.netlify.com)
- Check GitHub Issues on your repository
