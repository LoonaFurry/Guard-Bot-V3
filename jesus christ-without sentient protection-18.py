import discord
from discord.ext import commands
from collections import defaultdict, deque
import asyncio
import datetime
import re
import emoji
import aiohttp
from dotenv import load_dotenv
import logging
from fuzzywuzzy import fuzz

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables from .env file
load_dotenv()

# Retrieve the Discord token and VirusTotal API key from environment variables
TOKEN = ('Your-Token-Here')
VIRUSTOTAL_API_KEY = ('Your-Token-Here')

# Ensure the token and API key are loaded securely
if not TOKEN or not VIRUSTOTAL_API_KEY:
    raise ValueError("DISCORD_TOKEN and/or VIRUSTOTAL_API_KEY environment variables are not set")

# Constants
SLOW_MODE_DELAY = 5  # seconds
DUPLICATE_RESET_TIME = 60  # seconds
DUPLICATE_MSG_THRESHOLD = 3
CAPITALIZATION_THRESHOLD = 0.5  # percentage
SPAM_THRESHOLD = 2
SPAM_TIME = 1  # seconds
RAID_THRESHOLD = 10
RAID_TIME = 300  # seconds
EMOJI_THRESHOLD = 5  # maximum number of emojis allowed in a message

# Initialize bot
intents = discord.Intents.default()
intents.message_content = True
intents.members = True  # Required to track member joins
bot = commands.Bot(command_prefix='/', intents=intents)

# Tracking dictionaries
user_messages = defaultdict(lambda: deque(maxlen=SPAM_THRESHOLD))
message_history = defaultdict(lambda: deque(maxlen=DUPLICATE_MSG_THRESHOLD))
last_reset_time = defaultdict(lambda: datetime.datetime.now(datetime.timezone.utc))
member_join_times = defaultdict(lambda: deque(maxlen=RAID_THRESHOLD))

async def update_status():
    statuses = [
        "Protecting the server!",
        "Monitoring for raids...",
        "Spam detection in progress!",
        "Keeping the chat safe.",
        "Guarding against spam and raids."
    ]
    status_index = 0
    while True:
        await bot.change_presence(activity=discord.Game(name=statuses[status_index]))
        logging.debug(f"Status updated to: {statuses[status_index]}")
        status_index = (status_index + 1) % len(statuses)
        await asyncio.sleep(60)

def count_emojis(text):
    """Count the number of emojis in a text."""
    return sum(1 for char in text if char in emoji.EMOJI_DATA)

def contains_excessive_emojis(text, threshold=EMOJI_THRESHOLD):
    """Check if the text contains more emojis than the threshold."""
    emoji_count = count_emojis(text)
    if emoji_count > threshold:
        logging.debug(f"Message contains excessive emojis ({emoji_count} > {threshold}): {text}")
        return True
    return False

def count_mentions(message):
    return len(message.mentions)

def is_link(message_content):
    return re.search(r'(https?://\S+)', message_content)

async def analyze_link_safety(url):
    async with aiohttp.ClientSession() as session:
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        async with session.post('https://www.virustotal.com/api/v3/urls', headers=headers, data={'url': url}) as response:
            if response.status == 200:
                json_response = await response.json()
                scan_id = json_response.get('data', {}).get('id')
                if scan_id:
                    async with session.get(f'https://www.virustotal.com/api/v3/analyses/{scan_id}', headers=headers) as result_response:
                        if result_response.status == 200:
                            result = await result_response.json()
                            last_analysis_stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                            if last_analysis_stats.get('malicious', 0) > 0:
                                logging.debug(f"Link is malicious: {url}")
                                return False
                            logging.debug(f"Link is safe: {url}")
                            return True
    logging.debug(f"Link analysis failed: {url}")
    return False

async def analyze_file_safety(file_url):
    async with aiohttp.ClientSession() as session:
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        try:
            async with session.get(file_url) as file_response:
                if file_response.status != 200:
                    logging.error(f"Failed to download file: {file_url}")
                    return False

                file_content = await file_response.read()

                data = aiohttp.FormData()
                data.add_field('file', file_content, filename='file', content_type='application/octet-stream')

                upload_url = 'https://www.virustotal.com/api/v3/files'
                async with session.post(upload_url, headers=headers, data=data) as response:
                    if response.status == 200:
                        json_response = await response.json()
                        file_id = json_response.get('data', {}).get('id')
                        if file_id:
                            analysis_url = f'https://www.virustotal.com/api/v3/analyses/{file_id}'
                            await asyncio.sleep(30)  # Wait for analysis to complete
                            async with session.get(analysis_url, headers=headers) as result_response:
                                if result_response.status == 200:
                                    result = await result_response.json()
                                    last_analysis_stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                                    if last_analysis_stats.get('malicious', 0) > 0:
                                        logging.debug(f"File is malicious: {file_url}")
                                        return False
                                    logging.debug(f"File is clean: {file_url}")
                                    return True
                                else:
                                    logging.error(f"Failed to get file analysis results: {result_response.status}")
                    else:
                        logging.error(f"Failed to upload file: {response.status}")
                        logging.error(f"Response body: {await response.text()}")
        except Exception as e:
            logging.error(f"File analysis failed: {e}")
    return False

async def check_for_raid(guild):
    current_time = datetime.datetime.now(datetime.timezone.utc)
    join_times = member_join_times[guild.id]

    if len(join_times) >= RAID_THRESHOLD:
        if (current_time - join_times[0]).total_seconds() <= RAID_TIME:
            logging.warning(f"Raid detected in guild: {guild.id}. Kicking all new members.")
            for member in guild.members:
                if (current_time - member.joined_at).total_seconds() <= RAID_TIME:
                    try:
                        await member.kick(reason="Raid detected")
                        logging.info(f"Kicked member {member.name} due to raid.")
                    except discord.Forbidden:
                        logging.error(f"Failed to kick member {member.name}.")
                    except Exception as e:
                        logging.error(f"Error kicking member {member.name}: {e}")
            WARN_MESSAGE = "Raid detected and stopped. New members were kicked to protect the server."
            await guild.text_channels[0].send(WARN_MESSAGE)
            member_join_times[guild.id].clear()

@bot.event
async def on_member_join(member):
    guild_id = member.guild.id
    current_time = datetime.datetime.now(datetime.timezone.utc)

    # Track join time for the guild
    member_join_times[guild_id].append(current_time)
    await check_for_raid(member.guild)
    
@bot.event
async def on_message(message):
    if message.author.bot:
        return

    # Handle excessive emojis
    if contains_excessive_emojis(message.content):
        await message.delete()
        await message.channel.send(f"{message.author.mention}, your message contained too many emojis and has been deleted.", delete_after=10)
        logging.debug(f"Deleted message due to excessive emojis: {message.content}")
        return

    # Handle excessive capitalization
    if len(message.content) > 0 and (sum(1 for c in message.content if c.isupper()) / len(message.content)) >= CAPITALIZATION_THRESHOLD:
        await message.delete()
        await message.channel.send(f"{message.author.mention}, please avoid excessive capitalization.", delete_after=10)
        logging.debug(f"Deleted message due to excessive capitalization: {message.content}")
        return

    # Handle duplicate and similar messages
    current_time = datetime.datetime.now(datetime.timezone.utc)
    user_history = message_history[message.author.id]

    def is_similar(existing_message, new_message, threshold=90):
        """Check if the new_message is similar to the existing_message based on the given threshold."""
        return fuzz.ratio(existing_message, new_message) > threshold

    # Check for duplicates or similar messages in the history
    duplicate_detected = False
    for msg in user_history:
        if msg['content'] == message.content or is_similar(msg['content'], message.content):
            duplicate_detected = True
            break

    if duplicate_detected:
        # Only delete the message if it is a duplicate
        if len(user_history) >= DUPLICATE_MSG_THRESHOLD - 1:
            await message.delete()
            await message.channel.send(f"{message.author.mention}, your duplicate or similar messages were detected and deleted.", delete_after=10)
            logging.debug(f"Deleted message due to duplication or similarity: {message.content}")

        # Add the message to history and clear it for this user
        message_history[message.author.id].append({'content': message.content, 'timestamp': current_time})
        return

    # Add new message to history
    user_history.append({'content': message.content, 'timestamp': current_time})

    # Handle spamming
    user_messages[message.author.id].append(current_time)
    if len(user_messages[message.author.id]) == SPAM_THRESHOLD:
        if (current_time - user_messages[message.author.id][0]).total_seconds() <= SPAM_TIME:
            await message.delete()
            await message.channel.send(f"{message.author.mention}, you are sending messages too quickly. Please slow down.", delete_after=10)
            logging.debug(f"Deleted message due to spamming: {message.content}")
            return

    # Handle suspicious links
    if is_link(message.content):
        if not await analyze_link_safety(message.content):
            await message.delete()
            await message.channel.send(f"{message.author.mention}, a suspicious link was detected and removed.", delete_after=10)
            logging.debug(f"Deleted message due to suspicious link: {message.content}")
            return

    # Handle file uploads
    if message.attachments:
        for attachment in message.attachments:
            if not await analyze_file_safety(attachment.url):
                await message.delete()
                await message.channel.send(f"{message.author.mention}, a file you uploaded was flagged as malicious and has been deleted.", delete_after=10)
                logging.debug(f"Deleted file upload due to safety concerns: {attachment.url}")
                return

@bot.event
async def on_message_edit(before, after):
    if before.author.bot:
        return

    if before.content != after.content:
        logging.info(f"Message edited from: '{before.content}' to: '{after.content}'")

@bot.event
async def on_ready():
    logging.info(f'Bot is ready. Logged in as {bot.user.name}')
    bot.loop.create_task(update_status())

bot.run(TOKEN)
