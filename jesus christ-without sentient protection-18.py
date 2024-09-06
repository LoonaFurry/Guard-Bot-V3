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
import unicodedata
import logging

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
CAPITALIZATION_THRESHOLD = 0.7  # percentage
SPAM_TIME = 1  # seconds
SPAM_THRESHOLD = 4  # number of messages in SPAM_TIME seconds
RAID_THRESHOLD = 10
RAID_TIME = 300  # seconds
EMOJI_THRESHOLD = 5  # maximum number of emojis allowed in a message
WARNING_LIMIT = 1  # number of warnings before muting
MUTE_DURATION_30S = 30  # seconds
MUTE_DURATION_5M = 300  # seconds

# Initialize bot
intents = discord.Intents.default()
intents.message_content = True
intents.members = True  # Required to track member joins
intents.guilds = True  # Required to track guild roles
bot = commands.Bot(command_prefix='/', intents=intents)

# Tracking dictionaries
user_messages = defaultdict(lambda: deque(maxlen=SPAM_THRESHOLD))
message_history = defaultdict(lambda: deque(maxlen=DUPLICATE_MSG_THRESHOLD))
last_reset_time = defaultdict(lambda: datetime.datetime.now(datetime.timezone.utc))
member_join_times = defaultdict(lambda: deque(maxlen=RAID_THRESHOLD))
spam_warnings = defaultdict(int)  # Track number of warnings for each user
muted_users = defaultdict(lambda: None)  # Track muted users

def normalize_text(text):
    """Normalize text by removing non-alphanumeric characters and converting to lowercase."""
    text = re.sub(r'[^\w\s]', '', text)  # Remove punctuation
    text = re.sub(r'\d+', '', text)      # Remove numbers
    text = unicodedata.normalize('NFKC', text)  # Normalize Unicode characters
    return text.lower()

def is_similar(existing_message, new_message, threshold=90):
    """Check if the new_message is similar to the existing_message based on the given threshold."""
    existing_message_normalized = normalize_text(existing_message)
    new_message_normalized = normalize_text(new_message)
    return fuzz.ratio(existing_message_normalized, new_message_normalized) > threshold

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

async def mute_user(member, duration):
    mute_role = discord.utils.get(member.guild.roles, name="Muted")
    if not mute_role:
        logging.error("Mute role not found. Please create a role named 'Muted'.")
        return

    try:
        await member.add_roles(mute_role)
        logging.info(f"Muted {member.name} for {duration} seconds.")
        await asyncio.sleep(duration)
        await member.remove_roles(mute_role)
        logging.info(f"Unmuted {member.name} after {duration} seconds.")
    except discord.Forbidden:
        logging.error(f"Failed to mute {member.name}.")
    except Exception as e:
        logging.error(f"Error muting {member.name}: {e}")

@bot.event
async def on_member_join(member):
    guild_id = member.guild.id
    current_time = datetime.datetime.now(datetime.timezone.utc)

    # Track join time for the guild
    member_join_times[guild_id].append(current_time)
    
    # Check for raid
    await check_for_raid(member.guild)

@bot.event
async def on_message(message):
    if message.author.bot:
        return

    current_time = datetime.datetime.now(datetime.timezone.utc)
    user_message_deque = user_messages[message.author.id]

    # Spam detection: Delete the third message within one second
    user_message_deque.append((message.content, current_time))
    if len(user_message_deque) > SPAM_THRESHOLD:
        time_diff = (current_time - user_message_deque[0][1]).total_seconds()
        if time_diff <= SPAM_TIME:
            if len(user_message_deque) >= SPAM_THRESHOLD:
                warning_message = await message.channel.send(f"{message.author.mention}, your message was deleted due to spam.")
                await message.delete()
                logging.warning(f"Deleted spam message from {message.author.name}.")
                user_message_deque.popleft()  # Remove the oldest message after deletion
                await asyncio.sleep(10)  # Wait for 10 seconds before deleting the warning message
                await warning_message.delete()  # Delete the warning message
        else:
            user_message_deque.popleft()  # Remove old messages if outside the time window

    # Slow mode: Check if user is sending messages too quickly
    last_message_time = user_message_deque[0][1] if user_message_deque else current_time
    if (current_time - last_message_time).total_seconds() < SLOW_MODE_DELAY:
        warning_message = await message.channel.send(f"{message.author.mention}, you are sending messages too quickly. Please wait a moment.")
        await message.delete()
        logging.warning(f"Deleted message from {message.author.name} due to slow mode.")
        await asyncio.sleep(10)  # Wait for 10 seconds before deleting the warning message
        await warning_message.delete()  # Delete the warning message
        return

    # Duplicate message detection
    message_history[message.author.id].append(message.content)
    if len(message_history[message.author.id]) >= DUPLICATE_MSG_THRESHOLD:
        recent_messages = list(message_history[message.author.id])
        if all(is_similar(recent_messages[-1], msg) for msg in recent_messages[:-1]):
            warning_message = await message.channel.send(f"{message.author.mention}, your message was deleted because it was a duplicate.")
            await message.delete()
            logging.warning(f"Deleted duplicate message from {message.author.name}.")
            await asyncio.sleep(10)  # Wait for 10 seconds before deleting the warning message
            await warning_message.delete()  # Delete the warning message
            return

    # Excessive capitalization detection
    if len(message.content) > 0:  # Avoid division by zero
        capitalization_ratio = sum(char.isupper() for char in message.content) / len(message.content)
        if capitalization_ratio > CAPITALIZATION_THRESHOLD:
            warning_message = await message.channel.send(f"{message.author.mention}, your message was deleted due to excessive capitalization.")
            await message.delete()
            logging.warning(f"Deleted message with excessive capitalization from {message.author.name}.")
            await asyncio.sleep(10)  # Wait for 10 seconds before deleting the warning message
            await warning_message.delete()  # Delete the warning message
            return

    # Emoji detection
    if contains_excessive_emojis(message.content):
        warning_message = await message.channel.send(f"{message.author.mention}, your message was deleted due to excessive emojis.")
        await message.delete()
        logging.warning(f"Deleted message with excessive emojis from {message.author.name}.")
        await asyncio.sleep(10)  # Wait for 10 seconds before deleting the warning message
        await warning_message.delete()  # Delete the warning message
        return

    # Link detection
    if is_link(message.content):
        link = re.search(r'(https?://\S+)', message.content).group(0)
        if not await analyze_link_safety(link):
            warning_message = await message.channel.send(f"{message.author.mention}, your message contained an unsafe link and has been deleted.")
            await message.delete()
            logging.warning(f"Deleted message with unsafe link from {message.author.name}.")
            await asyncio.sleep(10)  # Wait for 10 seconds before deleting the warning message
            await warning_message.delete()  # Delete the warning message
        else:
            await message.channel.send(f"{message.author.mention}, your message contained a safe link.")
        return

    # File attachment safety
    if message.attachments:
        for attachment in message.attachments:
            try:
                file_url = attachment.url
                if not await analyze_file_safety(file_url):
                    warning_message = await message.channel.send(f"{message.author.mention}, your message contained an unsafe file and has been deleted.")
                    await message.delete()
                    logging.warning(f"Deleted message with unsafe file from {message.author.name}.")
                    await asyncio.sleep(10)  # Wait for 10 seconds before deleting the warning message
                    await warning_message.delete()  # Delete the warning message
                else:
                    await message.channel.send(f"{message.author.mention}, your message contained a safe file.")
            except Exception as e:
                logging.error(f"Error analyzing file attachment: {e}")
                return

    # Handle warnings for spamming
    if message.author.id in spam_warnings:
        if spam_warnings[message.author.id] >= WARNING_LIMIT:
            await mute_user(message.author, MUTE_DURATION_5M)
            spam_warnings[message.author.id] = 0  # Reset warnings after muting
        else:
            spam_warnings[message.author.id] += 1

    # Process commands and other messages
    await bot.process_commands(message)


@bot.event
async def on_ready():
    logging.info(f'Logged in as {bot.user.name}')
    bot.loop.create_task(update_status())

bot.run(TOKEN)
