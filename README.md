# DGWA (Discord_GWorkspace_Auth)

Discord bot for assigning roles based on the groups a user belongs to in Google Workspace

## Development

1. Clone the repository
2. Install Docker Desktop
3. Create a `.env` file in the root directory of the project with the following content:
    ```bash
    DGWA_GOOGLE_CLIENT_SECRETS=<JSON_CREDENTIAL_CONTENTS>
    DGWA_DISCORD_BOT_TOKEN=<DISCORD_BOT_TOKEN>
    # Local for development
    DGWA_GOOGLE_AUTH_REDIRECT_URI=http://127.0.0.1:5000
    # Will get sent a message when auth token needs to be refreshed
    DGWA_ADMIN_USER_ID=<DISCORD_USER_ID>
    # Optional, defaults shown
    DGWA_TOKEN_FILE=group_read_token.json
    ```
4. Run the bot with `docker compose up DGWA-bot` or `docker compose up -d DGWA-bot` to run in the background

## Setup for production

The bot should already be hosted in /opt/DGWA on the server, but if something happened
to it, here is a general outline of how to set it up.

1. Get access to our project in Google Cloud Platform
2. Download the OAuth 2.0 credentials for "Discord Bot" as a JSON file
3. Get access to our Discord Developer Portal Team
4. Generate a new bot token for the Discord bot
5. Copy `.env.example` to `.env` and fill in the necessary values
6. Make sure `discord-auth.robotiklubi.ee` points to the server where the bot will be hosted
7. Run the bot with `docker compose up -d`
8. Optionally use `docker-compose-dgwa.service.example` to make the bot start on boot
9. Use a reverse proxy to route traffic from `discord-auth.robotiklubi.ee` to the Python server running on port 5000
