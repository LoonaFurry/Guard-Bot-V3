import discord
from discord.ext import commands
from collections import defaultdict, deque
import asyncio
import datetime
import re
import emoji
import aiohttp
import os
from dotenv import load_dotenv
from fuzzywuzzy import fuzz
import logging

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables from .env file
load_dotenv()

# Retrieve the Discord token and VirusTotal API key from environment variables
TOKEN = ('Token-Here')
VIRUSTOTAL_API_KEY = ('Token-Here')

# Ensure the token and API key are loaded securely
if not TOKEN or not VIRUSTOTAL_API_KEY:
    raise ValueError("DISCORD_TOKEN and/or VIRUSTOTAL_API_KEY environment variables are not set")

# Constants
SWEARS = [
    "siktir", "siktir be", "sik", "sikim", "sikiyim", "sikiyim seni",
    "yarrak", "sik kafalı", "yarrak kafalı", "yarrak kafası", "yarrak kafa",
    "sikeyim", "sikeyim seni", "engelli", "özürlü", "aptal", "beyinsiz",
    "salak", "mal", "gerizekalı", "deli", "ruh hastası", "ağzına sıçayım",
    "amk", "mk", "am"
]
SLOW_MODE_DELAY = 5  # seconds
DUPLICATE_RESET_TIME = 60  # seconds
DUPLICATE_MSG_THRESHOLD = 3
CAPITALIZATION_THRESHOLD = 0.5  # percentage
SPAM_THRESHOLD = 5
SPAM_TIME = 60  # seconds
RAID_THRESHOLD = 10
RAID_TIME = 300  # seconds
FUZZY_MATCH_THRESHOLD = 80
EMOJI_THRESHOLD = 5  # maximum number of emojis allowed in a message

# Initialize bot
intents = discord.Intents.default()
intents.message_content = True
intents.members = True  # Required to track member joins
bot = commands.Bot(command_prefix='/', intents=intents)

# Tracking dictionaries
user_messages = defaultdict(lambda: deque(maxlen=SPAM_THRESHOLD))
duplicate_messages = defaultdict(int)
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

def compile_swear_patterns(swears):
    """Compile regex patterns for swear words."""
    return [re.compile(r'\b' + re.escape(swear) + r'\b', re.IGNORECASE) for swear in swears]

SWEAR_PATTERNS = compile_swear_patterns(SWEARS)

def contains_swear(message_content):
    sanitized_content = re.sub(r'[^\w\s]', '', message_content.lower())
    for pattern in SWEAR_PATTERNS:
        if pattern.search(sanitized_content):
            logging.debug(f"Message contains swear word: {pattern.pattern}")
            return True
    for swear in SWEARS:
        if isinstance(swear, str) and fuzz.partial_ratio(swear, sanitized_content) >= FUZZY_MATCH_THRESHOLD:
            logging.debug(f"Message contains fuzzy matched swear word: {swear}")
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

    # Handle swearing
    if contains_swear(message.content):
        await message.delete()
        await message.channel.send(f"{message.author.mention}, your message contained inappropriate language.", delete_after=10)
        logging.debug(f"Deleted message due to swearing: {message.content}")
        return

    # Handle excessive capitalization
    if sum(1 for c in message.content if c.isupper()) / len(message.content) >= CAPITALIZATION_THRESHOLD:
        await message.delete()
        await message.channel.send(f"{message.author.mention}, please avoid excessive capitalization.", delete_after=10)
        logging.debug(f"Deleted message due to excessive capitalization: {message.content}")
        return

    # Handle duplicate messages
    last_reset = last_reset_time[message.author.id]
    current_time = datetime.datetime.now(datetime.timezone.utc)

    if (current_time - last_reset).total_seconds() > DUPLICATE_RESET_TIME:
        duplicate_messages[message.author.id] = 0
        last_reset_time[message.author.id] = current_time

    if duplicate_messages[message.author.id] > DUPLICATE_MSG_THRESHOLD:
        await message.delete()
        await message.channel.send(f"{message.author.mention}, you have sent too many duplicate messages.", delete_after=10)
        logging.debug(f"Deleted message due to duplication: {message.content}")
        return

    duplicate_messages[message.author.id] += 1

    # Handle spamming
    user_messages[message.author.id].append(current_time)
    if len(user_messages[message.author.id]) == SPAM_THRESHOLD:
        if (current_time - user_messages[message.author.id][0]).total_seconds() <= SPAM_TIME:
            await message.delete()
            await message.channel.send(f"{message.author.mention}, please slow down. You are sending messages too quickly.", delete_after=10)
            logging.debug(f"Deleted message due to spamming: {message.content}")
            return

    # Handle suspicious links
    if is_link(message.content):
        is_safe = await analyze_link_safety(message.content)
        if not is_safe:
            await message.delete()
            await message.channel.send(f"{message.author.mention}, the link you posted is potentially harmful and has been removed.", delete_after=10)
            logging.debug(f"Deleted potentially harmful link: {message.content}")
            return

    await bot.process_commands(message)  # Allow other commands to run after checks

@bot.command(name='ping')
async def ping(ctx):
    await ctx.send('Pong!')

@bot.event
async def on_ready():
    logging.info(f'Bot connected as {bot.user}')
    bot.loop.create_task(update_status())

if __name__ == '__main__':
    bot.run(TOKEN)
