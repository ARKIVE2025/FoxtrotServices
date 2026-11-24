# Foxtrot quote backend

One Cloud Function, `quote`, that replaces Formspree for the website quote
form and lets Muse read new quotes.

- `POST https://us-central1-<project>.cloudfunctions.net/quote`
  (public, no key) — the quote form sends a quote; it is validated and
  stored in Firestore collection `foxtrotQuotes` with `status: "new"`.
  A honeypot field and a light per-IP rate limit keep out basic spam.
- `GET` the same URL with header `x-foxtrot-key: <FOXTROT_KEY>`
  (key-guarded) — returns stored quotes, newest first, for Muse.

## First-time setup

1. Pick the Firebase project (recommended: reuse the existing FFM project
   `ffmanager-a7075`, which already runs Cloud Functions — see
   `.firebaserc`). A separate project also works but needs its own billing
   setup for Cloud Functions.
2. Set the read key as a secret (never commit it):
   `firebase functions:secrets:set FOXTROT_KEY`
   and give the same value to Muse through its secure credential flow.
3. Install and deploy from this directory:
   `npm install`
   `firebase deploy --only functions:quote`
4. The website form already points at the function URL in `index.html`.
   If the project changes, update the form `action` and the `QUOTE_URL`
   in the page script to match.
