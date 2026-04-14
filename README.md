# ep_oauth

OAuth2 authentication for Etherpad via GitHub.

## Install

```
pnpm run plugins i ep_oauth
```

## Settings

Add to your `settings.json`:

```json
"ep_oauth": {
  "clientID": "your_github_client_id",
  "clientSecret": "your_github_client_secret",
  "callbackURL": "https://your-etherpad.example.com/auth/callback"
}
```

## License

Apache-2.0
