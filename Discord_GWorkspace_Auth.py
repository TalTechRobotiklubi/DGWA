import json
import os
import re
import logging
import discord
import asyncio
from dotenv import load_dotenv
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow, InstalledAppFlow
from googleapiclient import discovery

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

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
    "https://www.googleapis.com/auth/admin.directory.group.readonly"
]

GUILD = "Robotiklubi"
GROUP_ROLE_PAIRS = {
    "juhatus@robotiklubi.ee": "Juhatus",
    "liikmed@robotiklubi.ee": "Liige",
    "aktivistid@robotiklubi.ee": "Liige",
    "vilistlased@robotiklubi.ee": "Vilistlane"
}
global_group_member_pairs = {}


async def create_auth_url_embed(authorization_url):
    embed = discord.Embed(title="Getting a role", color=0x00ff00)
    embed.add_field(name="Step 1", value="Click on the link below", inline=False)
    embed.add_field(name="Step 2", value="Login. Ignore the \"This site can’t be reached\" error", inline=False)
    embed.add_field(name="Step 3", value="Post the resulting URL in this chat", inline=False)
    embed.add_field(name="Link", value=f"[Click me!]({authorization_url})", inline=False)
    embed.set_footer(text="If you don't answer within 120s, you will have to restart the process.")
    return embed


async def handle_response(response, state, member):
    if response.content == "CANCEL":
        await member.send("Canceling process")
        return False
    if "https://127.0.0.1/" in response.content:
        if state not in response.content:
            await member.send("Incorrect URL")
            return True
        pattern = r"(?:https://127\.0\.0\.1/\?.*code=)(.+?)(?:&scope=|$)(?:.*group.readonly)"
        code = re.search(pattern, response.content).group(1)
        if not code:
            await member.send("No authorization code in the given URL")
            return True
    else:
        await member.send("Incorrect URL or timed out")
        return True
    return False


class Bot:
    def __init__(self, token, intents):
        self.client = discord.Client(intents=intents)
        self.token = token

        @self.client.event
        async def on_ready():
            logging.info(f'Logged in as {self.client.user}')
            await self.client.loop.create_task(self.refresh_members_list_periodically())

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

        if isinstance(message.channel, discord.channel.DMChannel):
            if "GET_ROLE" in message.content:
                await self.process_get_role_request(message)
            elif "REFRESH_LOADED_WORKSPACE_GROUPS" in message.content:
                await self.refresh_members_list(message)

    async def process_get_role_request(self, message):
        groups = await self.get_user_groups(message.author)
        if groups:
            author = message.author
            guild = discord.utils.get(self.client.guilds, name=GUILD)
            member = guild.get_member(author.id)
            if not member:
                logging.warning(f"No member found with author id: {author.id}")

            for key, value in GROUP_ROLE_PAIRS.items():
                if key in groups:
                    role = discord.utils.get(guild.roles, name=value)
                    await member.add_roles(role)
                    logging.info(f"Added role {role.name} to {member.name}")
                    await member.send(f"Role '{role.name}' added")

    async def get_user_groups(self, member):
        logging.info(f"Sending embed to {member.name}")

        flow = Flow.from_client_config(
            client_config=GOOGLE_CLIENT_SECRETS,
            scopes=GOOGLE_SCOPES,
            redirect_uri=GOOGLE_AUTH_REDIRECT_URI
        )

        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )

        embed = await create_auth_url_embed(authorization_url)
        await member.send(embed=embed)
        dm_chan = await member.create_dm()

        try:
            response = await self.client.wait_for("message", check=lambda m: m.channel == dm_chan, timeout=120.0)
        except Exception:
            logging.error("Timed out")
            await member.send("Timed out, type GET_ROLE to start again")
            raise

        if await handle_response(response, state, member):
            return await self.get_user_groups(member)

        logging.info(f"Processing {member.name}")

        flow.fetch_token(authorization_response=response.content)
        session = flow.authorized_session()
        profile_info = session.get('https://www.googleapis.com/userinfo/v2/me').json()

        user_in_groups = []
        for email, members in global_group_member_pairs.items():
            if profile_info['email'] in members:
                user_in_groups.append(email)

        return user_in_groups

    async def get_refresh_credentials(self, message, attempt=0):
        if attempt > 2:
            logging.error("Failed to get credentials for refreshing members list (maximum attempts exceeded)")
            if message:
                await message.author.send("Amount of attempts exceeded. Please try again later.")
            return None

        if not attempt:
            logging.info(f"Getting credentials for refreshing members list")
        else:
            logging.info(f"Retry attempt {attempt}: Getting credentials for refreshing members list.")

        credentials = None
        if os.path.exists(TOKEN_FILE):
            logging.debug("Token file exists, using it")
            credentials = Credentials.from_authorized_user_file(TOKEN_FILE, GOOGLE_SCOPES)

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
            GOOGLE_CLIENT_SECRETS,
            scopes=['https://www.googleapis.com/auth/admin.directory.group.readonly'],
            redirect_uri=GOOGLE_AUTH_REDIRECT_URI
        )
        if message:
            # If refresh is initiated by a user, send them the authorization link
            logging.info("Sending authorization link to user who initiated refresh")
            await message.author.send(f"[Authorization link]({flow.authorization_url()[0]})\n\n"
                                      f"Click the link above and enter the code here.")
            dm_chan = message.channel
            try:
                response = await self.client.wait_for("message",
                                                      check=(lambda m: m.channel == dm_chan),
                                                      timeout=120.0)
                flow.fetch_token(authorization_response=response.content)
                credentials = flow.credentials
            except asyncio.TimeoutError:
                await message.author.send("Timed out")
                logging.error("Timed out waiting for user to refresh token")
                return None
            except Exception as e:
                await message.author.send("Error occurred, please try again")
                logging.error(f"Error: {e}")
                return self.get_refresh_credentials(message, attempt + 1)
        else:
            # Initiate conversation with Tech Lead for token refresh
            logging.info("Sending authorization link to tech lead")
            tech_lead_user = self.client.get_user(ADMIN_USER_ID)
            await tech_lead_user.send(f"The bot's token has expired. Please refresh it.")
            message = await tech_lead_user.send(f"[Authorization link]({flow.authorization_url()[0]})\n\n"
                                                f"Click the link above and enter the code here.")
            dm_chan = message.channel
            response = await self.client.wait_for("message",
                                                  check=(lambda m: m.channel == dm_chan),
                                                  timeout=300.0)
            try:
                flow.fetch_token(authorization_response=response.content)
                credentials = flow.credentials
            except asyncio.TimeoutError:
                await tech_lead_user.send("Timed out")
                logging.error("Timed out waiting for tech lead to refresh token")
                return None
            except Exception as e:
                await tech_lead_user.send("Error occurred, please try again")
                logging.error(f"Error: {e}")
                return self.get_refresh_credentials(response, attempt + 1)

        with open(TOKEN_FILE, "w") as token:
            token.write(credentials.to_json())
        return credentials

    async def refresh_members_list(self, message=None):
        credentials = await self.get_refresh_credentials(message)
        if not credentials:
            logging.error("Failed to get credentials for refreshing members list")
            return
        logging.info("Successfully got credentials for refreshing members list")

        query_service = discovery.build('admin', 'directory_v1', credentials=credentials)
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

    def run(self):
        self.client.run(self.token)


if __name__ == '__main__':
    # Load env variables
    load_dotenv()
    GOOGLE_CLIENT_SECRETS = json.loads(os.getenv('DGWA_GOOGLE_CLIENT_SECRETS'))
    DISCORD_BOT_TOKEN = os.getenv('DGWA_DISCORD_BOT_TOKEN')
    GOOGLE_AUTH_REDIRECT_URI = os.getenv('DGWA_GOOGLE_AUTH_REDIRECT_URI')
    TOKEN_FILE = os.getenv('DGWA_TOKEN_FILE', 'group_read_token.json')
    ADMIN_USER_ID = os.getenv('DGWA_ADMIN_USER_ID')

    bot = Bot(intents=INTENTS, token=DISCORD_BOT_TOKEN)
    bot.run()
