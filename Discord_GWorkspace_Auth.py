import json
import os
import logging
from multiprocessing.connection import Listener
from os import access

import discord
import asyncio
import ssl
from dotenv import load_dotenv
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow, InstalledAppFlow
from googleapiclient import discovery
from aiohttp import web

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Discord bot variables
INTENTS = discord.Intents.default()
INTENTS.members = True
INTENTS.guilds = True
INTENTS.messages = True
INTENTS.message_content = True

# Google API variables
GOOGLE_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]

GOOGLE_ADMIN_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.member.readonly",
    "https://www.googleapis.com/auth/admin.directory.user",
]

GUILD = "Robotiklubi"
GROUP_ROLE_PAIRS = {
    "juhatus@robotiklubi.ee": "Juhatus",
    "liikmed@robotiklubi.ee": "Liige",
    "aktivistid@robotiklubi.ee": "Liige",
    "vilistlased@robotiklubi.ee": "Vilistlane"
}
global_group_member_pairs = {}

# This will map state -> (flow, user_id, future)
state_flows = {}


async def create_auth_url_embed(authorization_url):
    embed = discord.Embed(title="Getting a role", color=0x00ff00)
    embed.add_field(name="Step 1", value="Click on the link below and sign in with your Google account.", inline=False)
    embed.add_field(name="Step 2", value="After login, you can close the browser tab. The bot will handle the rest.",
                    inline=False)
    embed.add_field(name="Link", value=f"[Click me!]({authorization_url})", inline=False)
    embed.set_footer(text="If you don't complete the process within 120s, you will have to restart.")
    return embed


class Bot:
    def __init__(self, token, intents):
        self.client = discord.Client(intents=intents)
        self.token = token

        # Optional listening channel and guild
        self.listen_channel_id = LISTEN_CHANNEL_ID
        self.listen_guild_id = LISTEN_GUILD_ID

        @self.client.event
        async def on_ready():
            logging.info(f'Logged in as {self.client.user}')
            # Start the periodic refresh in the background
            self.client.loop.create_task(self.refresh_members_list_periodically())
            # Start the web server in the background
            self.client.loop.create_task(self.start_web_server())

        @self.client.event
        async def on_member_join(member):
            await self.handle_member_join(member)

        @self.client.event
        async def on_message(message):
            await self.handle_message(message)

    async def handle_member_join(self, member):
        groups = await self.get_user_groups(member)
        guild = discord.utils.get(self.client.guilds, name=GUILD)

        for key, value in GROUP_ROLE_PAIRS.items():
            if key in groups:
                role = discord.utils.get(guild.roles, name=value)
                await member.add_roles(role)
                logging.info(f"Added role {role.name} to {member.name}")

    async def handle_message(self, message):
        if message.author == self.client.user:
            return

        # Check if message is in DM
        is_dm = isinstance(message.channel, discord.channel.DMChannel)

        # Check if message is in the configured channel (if set)
        is_listen_channel = False
        if self.listen_channel_id:
            if (message.channel.id == int(self.listen_channel_id) and
                    (self.listen_guild_id is None or (
                            message.guild and str(message.guild.id) == self.listen_guild_id))):
                is_listen_channel = True

        # If we are in DM or the configured channel and the user requested GET_ROLE
        if ("GET_ROLE" in message.content) and (is_dm or is_listen_channel):
            # If the message is not a DM (which means it's in a server), delete it
            if not is_dm:
                try:
                    await message.delete()
                except discord.Forbidden:
                    logging.warning("Bot does not have permission to delete messages.")
                except discord.NotFound:
                    logging.warning("Message already deleted or not found.")
            await self.process_get_role_request(message)
        elif "REFRESH_LOADED_WORKSPACE_GROUPS" in message.content and is_dm:
            await self.refresh_members_list(message)

    async def process_get_role_request(self, message):
        # Determine the member to get roles for
        if isinstance(message.channel, discord.channel.DMChannel):
            # Author is the member
            author = message.author
            guild = discord.utils.get(self.client.guilds, name=GUILD)
            member = guild.get_member(author.id)
        else:
            # If not DM, we must have guild and a sender
            member = message.guild.get_member(message.author.id)

        if not member:
            logging.warning(f"No member found for author id: {message.author.id}")
            return

        groups = await self.get_user_groups(member)
        if groups:
            for key, value in GROUP_ROLE_PAIRS.items():
                if key in groups:
                    role = discord.utils.get(member.guild.roles, name=value)
                    await member.add_roles(role)
                    logging.info(f"Added role {role.name} to {member.name}")
                    await member.send(f"Role '{role.name}' added")

    async def get_user_groups(self, member):
        logging.info(f"Starting OAuth flow for {member.name}")

        # Create a unique Flow and state for this authentication attempt
        flow = Flow.from_client_config(
            client_config=GOOGLE_CLIENT_SECRETS,
            scopes=GOOGLE_SCOPES,
            redirect_uri=GOOGLE_AUTH_REDIRECT_URI
        )

        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )

        # Create a future that will be set once we get the code from callback
        code_future = asyncio.Future()
        logging.info(f"Created OAuth flow for {member.name} with state {state}")
        state_flows[state] = (flow, member.id, code_future)

        embed = await create_auth_url_embed(authorization_url)
        await member.send(embed=embed)

        # Wait for the code to come through the web callback or timeout
        try:
            await asyncio.wait_for(code_future, timeout=120.0)
        except asyncio.TimeoutError:
            logging.error("Timed out waiting for OAuth callback")
            await member.send("Timed out, type GET_ROLE to start again")
            # Cleanup the state
            state_flows.pop(state, None)
            return []

        # Once we have the code (set in the callback), we can fetch the token
        code = code_future.result()
        credentials = flow.credentials
        session = flow.authorized_session()
        profile_info = session.get('https://www.googleapis.com/userinfo/v2/me').json()

        # Determine which groups the user is in
        user_in_groups = []
        for email, members in global_group_member_pairs.items():
            if profile_info['email'] in members:
                user_in_groups.append(email)

        # Now we attempt to set the Discord UID in the user's Google Directory profile
        admin_credentials = await self.get_refresh_credentials()
        if admin_credentials is None:
            logging.error("Failed to update Discord UID because admin credentials are not available.")
        else:
            # Build the Directory API service with admin credentials
            service = discovery.build('admin', 'directory_v1', credentials=admin_credentials, cache_discovery=False)

            try:
                # Patch the user's custom schema field "Accounts" -> "Discord_UID"
                service.users().patch(
                    userKey=profile_info['email'],
                    body={
                        "customSchemas": {
                            "Accounts": {
                                "Discord_UID": str(member.id)  # Store the member's Discord user ID
                            }
                        }
                    }
                ).execute()
                logging.info(f"Set Discord UID {member.id} for user {profile_info['email']}.")
            except Exception as e:
                logging.error(f"Failed to set Discord UID for user {profile_info['email']}: {e}")

        return user_in_groups

    async def get_refresh_credentials(self, message=None, attempt=0):
        if attempt > 2:
            logging.error("Failed to get credentials for refreshing members list (maximum attempts exceeded)")
            if message:
                await message.author.send("Amount of attempts exceeded. Please try again later.")
            return None

        logging.info(f"Attempt {attempt}: Getting credentials for refreshing members list.")

        credentials = None
        if os.path.exists(TOKEN_FILE):
            logging.debug("Token file exists, using it")
            credentials = Credentials.from_authorized_user_file(TOKEN_FILE, GOOGLE_ADMIN_SCOPES)

        # If saved credentials exist and are still valid, return them
        if credentials and credentials.valid:
            logging.info("Using saved credentials from token file")
            return credentials

        # If saved credentials exist but are expired, refresh them
        if credentials and credentials.expired and credentials.refresh_token:
            logging.info("Token file exists but is expired, refreshing credentials")
            credentials.refresh(Request())
            with open(TOKEN_FILE, "w") as token:
                token.write(credentials.to_json())
            return credentials

        # Need to get new credentials
        flow = InstalledAppFlow.from_client_config(
            ADMIN_AUTH_CLIENT_SECRETS,
            scopes=GOOGLE_ADMIN_SCOPES,
            redirect_uri=GOOGLE_AUTH_REDIRECT_URI
        )

        auth_url, state = flow.authorization_url(access_type='offline', prompt='consent')
        code_future = asyncio.Future()
        state_flows[state] = (flow, message.author.id if message else ADMIN_USER_ID, code_future)

        if message:
            await message.author.send(f"Please click the following link to authorize:\n{auth_url}")
        else:
            tech_lead_user = self.client.get_user(int(ADMIN_USER_ID))
            await tech_lead_user.send(
                f"The bot's token has expired. Please authorize by clicking the link below:\n{auth_url}")

        try:
            await asyncio.wait_for(code_future, timeout=300.0)
            credentials = flow.credentials
        except asyncio.TimeoutError:
            logging.error("Timed out waiting for authorization")
            if message:
                await message.author.send("Authorization timed out. Please try again.")
            else:
                tech_lead_user = self.client.get_user(int(ADMIN_USER_ID))
                await tech_lead_user.send("Authorization timed out. Please try again.")
            return None
        except Exception as e:
            logging.error(f"Error during authorization: {e}")
            if message:
                await message.author.send("An error occurred during authorization. Please try again.")
            else:
                tech_lead_user = self.client.get_user(int(ADMIN_USER_ID))
                await tech_lead_user.send("An error occurred during authorization. Please try again.")
            return None
        finally:
            state_flows.pop(state, None)

        with open(TOKEN_FILE, "w") as token:
            token.write(credentials.to_json())
        return credentials

    async def refresh_members_list(self, message=None):
        credentials = await self.get_refresh_credentials(message)
        if not credentials:
            logging.error("Failed to get credentials for refreshing members list")
            return
        logging.info("Successfully got credentials for refreshing members list")

        query_service = discovery.build('admin', 'directory_v1', credentials=credentials, cache_discovery=False)
        results_groups = query_service.groups().list(domain='robotiklubi.ee', maxResults=400).execute()
        groups = results_groups.get('groups', [])

        emails = [group.get('email', []) for group in groups]

        for email in emails:
            results_members = query_service.members().list(maxResults=400, groupKey=email).execute()
            members = results_members.get('members', [])
            member_emails = [member.get('email', []) for member in members]
            global_group_member_pairs[email] = member_emails

        if message:
            await message.author.send(f"Keys: {global_group_member_pairs.keys()}\nSuccessfully loaded members lists")

    async def refresh_members_list_periodically(self):
        while True:
            await self.refresh_members_list()
            await asyncio.sleep(3600)  # Sleep for one hour

    async def start_web_server(self):
        app = web.Application()
        app.add_routes([web.get('/', self.handle_callback)])
        runner = web.AppRunner(app)
        await runner.setup()

        # Create SSL context
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain('data/cert.pem', 'data/key.pem')

        # Start HTTPS server on port 5000
        site = web.TCPSite(runner, '0.0.0.0', 5000, ssl_context=ssl_context)
        await site.start()
        logging.info("Web server started on https://0.0.0.0:5000")

    async def handle_callback(self, request):
        code = request.query.get('code')
        state = request.query.get('state')
        if not code or not state:
            return web.Response(text="Missing code or state", status=400)

        logging.debug(f"Received callback with code {code} and state {state}")
        entry = state_flows.get(state)
        if not entry:
            return web.Response(text="Invalid or expired state", status=400)

        flow, user_id, code_future = entry
        try:
            flow.fetch_token(authorization_response=str(request.url))
            if not code_future.done():
                code_future.set_result(code)
        except Exception as e:
            logging.error(f"Error completing OAuth flow: {e}")
            if not code_future.done():
                code_future.set_exception(e)
            return web.Response(text="Error completing OAuth flow", status=500)
        finally:
            state_flows.pop(state, None)

        return web.Response(text="Authorization complete! You can close this window.")

    def run(self):
        self.client.run(self.token)


def check_not_empty(value, name):
    if not value:
        raise ValueError(f"{name} is not set, but required. Please set it in the .env file.")
    return value


if __name__ == '__main__':
    # Load env variables
    load_dotenv()
    GOOGLE_CLIENT_SECRETS = json.loads(
        check_not_empty(os.getenv('DGWA_GOOGLE_CLIENT_SECRETS'), 'DGWA_GOOGLE_CLIENT_SECRETS'))
    ADMIN_AUTH_CLIENT_SECRETS = json.loads(
        check_not_empty(os.getenv('DGWA_ADMIN_AUTH_CLIENT_SECRETS'), 'DGWA_ADMIN_AUTH_CLIENT_SECRETS'))
    DISCORD_BOT_TOKEN = check_not_empty(os.getenv('DGWA_DISCORD_BOT_TOKEN'), 'DGWA_DISCORD_BOT_TOKEN')
    GOOGLE_AUTH_REDIRECT_URI = check_not_empty(os.getenv('DGWA_GOOGLE_AUTH_REDIRECT_URI'), 'DGWA_GOOGLE_AUTH_REDIRECT_URI')
    TOKEN_FILE = os.getenv('DGWA_TOKEN_FILE', 'data/group_read_token.json')
    ADMIN_USER_ID = check_not_empty(os.getenv('DGWA_ADMIN_USER_ID'), 'DGWA_ADMIN_USER_ID')
    LOG_LEVEL = os.getenv('DGWA_LOG_LEVEL', 'INFO').upper()

    LISTEN_CHANNEL_ID = os.getenv('DGWA_LISTEN_CHANNEL_ID')
    LISTEN_GUILD_ID = os.getenv('DGWA_LISTEN_GUILD_ID')
    # If one is set, both must be set
    if LISTEN_CHANNEL_ID and not LISTEN_GUILD_ID:
        raise ValueError("If LISTEN_CHANNEL_ID is set, LISTEN_GUILD_ID must be set as well.")
    if LISTEN_GUILD_ID and not LISTEN_CHANNEL_ID:
        raise ValueError("If LISTEN_GUILD_ID is set, LISTEN_CHANNEL_ID must be set as well.")

    # Check that the log level is valid
    if LOG_LEVEL not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
        logging.warning(f"Invalid log level '{LOG_LEVEL}', defaulting to 'INFO'")
        LOG_LEVEL = 'INFO'

    logging.getLogger().setLevel(LOG_LEVEL)

    bot = Bot(intents=INTENTS, token=DISCORD_BOT_TOKEN)
    bot.run()
