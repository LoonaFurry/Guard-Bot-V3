import discord
from discord.ext import commands
from collections import defaultdict, deque
import asyncio
import datetime
import re
import emoji
import aiohttp
from dotenv import load_dotenv
from fuzzywuzzy import fuzz
import unicodedata
import logging
import hashlib
import io
from PIL import Image
import numpy as np
import torch
from transformers import AutoTokenizer, AutoFeatureExtractor, AutoModelForImageClassification
from sklearn.ensemble import RandomForestClassifier, IsolationForest
import pickle  
from sklearn.model_selection import train_test_split  
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import random
from sklearn.preprocessing import StandardScaler  
from sklearn.cluster import DBSCAN  
import pandas as pd  
from textblob import TextBlob  
from sklearn.preprocessing import MinMaxScaler  
import networkx as nx  
from scipy.stats import zscore  
from river import anomaly  
import requests  
import json  
import sqlite3

# --- Setup ---
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
load_dotenv()
TOKEN = ('YOUR_BOT_TOKEN')  
VIRUSTOTAL_API_KEY = ('YOUR_VIRUSTOTAL_API_KEY')
CLOUDFLARE_API_KEY = ('YOUR_CLOUDFLARE_API_KEY') 

# --- Constants ---
SLOW_MODE_DELAY = 5
DUPLICATE_RESET_TIME = 60
DUPLICATE_MSG_THRESHOLD = 3
CAPITALIZATION_THRESHOLD = 0.7
SPAM_TIME = 1
SPAM_THRESHOLD = 4
RAID_THRESHOLD = 10
RAID_TIME = 300
EMOJI_THRESHOLD = 5
WARNING_LIMIT = 1
MUTE_DURATION_30S = 30
MUTE_DURATION_5M = 300
IMAGE_DUPLICATE_TIME_WINDOW = 60
SUSPICIOUS_ACTIVITY_THRESHOLD = 3
MESSAGE_VOLUME_THRESHOLD = 10
JOIN_RATE_THRESHOLD = 5

# --- Initialize Bot ---
intents = discord.Intents.default()
intents.message_content = True
intents.members = True
intents.guilds = True
intents.presences = True 
bot = commands.Bot(command_prefix='/', intents=intents)

# --- Tracking Dictionaries ---
user_messages = defaultdict(lambda: deque(maxlen=SPAM_THRESHOLD))
message_history = defaultdict(lambda: deque(maxlen=DUPLICATE_MSG_THRESHOLD))
user_image_hashes = defaultdict(list)
member_join_times = defaultdict(lambda: deque(maxlen=RAID_THRESHOLD))
suspicious_accounts = set()
spam_warnings = defaultdict(int)

# --- Database ---
db_name = "user_data.db"

# --- ML Model ---
ml_model_filename = "raid_detection_model.pkl"
ml_model = None
anomaly_threshold = -0.5

# --- Helper Functions ---
def normalize_text(text):
    text = re.sub(r'[^\w\s]', '', text)
    text = re.sub(r'\d+', '', text)
    text = unicodedata.normalize('NFKC', text)
    return text.lower()

def is_similar(existing_message, new_message, threshold=90):
    existing_message_normalized = normalize_text(existing_message)
    new_message_normalized = normalize_text(new_message)
    return fuzz.ratio(existing_message_normalized, new_message_normalized) >= threshold

async def update_status():
    statuses = [
        "Monitoring the server...",
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
    return sum(1 for char in text if char in emoji.EMOJI_DATA)

def contains_excessive_emojis(text, threshold=EMOJI_THRESHOLD):
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
                            await asyncio.sleep(30)
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

def extract_user_features(member):
    current_time = datetime.datetime.now(datetime.timezone.utc)
    account_age_days = (current_time - member.created_at).days
    account_age_weeks = account_age_days / 7

    features = [
        account_age_weeks,
        member.guild.member_count,
        member.guild.premium_subscription_count,
        int(member.top_role.position),
        member.discriminator
    ]
    return features

async def check_for_raid(guild):
    current_time = datetime.datetime.now(datetime.timezone.utc)
    join_times = member_join_times[guild.id]

    if len(join_times) >= RAID_THRESHOLD:
        if (current_time - join_times[0]).total_seconds() <= RAID_TIME:
            logging.warning(f"Raid detected in guild: {guild.id}. Kicking all new members.")
            for member in guild.members:
                if (current_time - member.joined_at).total_seconds() <= RAID_TIME:
                    suspicious_accounts.add(member.id)
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

    global ml_model
    if ml_model:
        for member in guild.members:
            if (current_time - member.joined_at).total_seconds() <= RAID_TIME:
                features = extract_user_features(member)
                prediction = ml_model.predict([features])[0]
                if prediction == 1:
                    suspicious_accounts.add(member.id)
                    try:
                        await member.kick(reason="Suspicious activity detected.")
                        logging.info(f"Kicked member {member.name} based on ML prediction.")
                    except discord.Forbidden:
                        logging.error(f"Failed to kick member {member.name}.")
                    except Exception as e:
                        logging.error(f"Error kicking member {member.name}: {e}")

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

async def hash_image(image_url):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(image_url) as response:
                image_data = await response.read()
                return hashlib.sha256(image_data).hexdigest()
    except Exception as e:
        logging.error(f"Error fetching image for hashing: {e}")
        return

def is_duplicate_image(user_id, image_hash, current_time):
    for hash, timestamp in user_image_hashes[user_id]:
        if hash == image_hash and (current_time - timestamp).total_seconds() <= IMAGE_DUPLICATE_TIME_WINDOW:
            return True
    return False

async def get_ip_from_cloudflare(user_id):
    headers = {'Authorization': f'Bearer {CLOUDFLARE_API_KEY}'}
    url = f'https://api.cloudflare.com/client/v4/accounts/your_account_id/user_agents/{user_id}'
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data.get('result', {}).get('ip', None)
    else:
        logging.error(f"Cloudflare API request failed with status code {response.status_code}")
        return None

async def analyze_user_data(user_id):
    global ml_model

    db_connection = sqlite3.connect(db_name)
    cursor = db_connection.cursor()
    cursor.execute("SELECT * FROM user_data WHERE user_id = ?", (user_id,))
    user_data = cursor.fetchone()
    db_connection.close()

    if user_data:
        messages, joins, roles, interactions, ip, suspicious_actions = user_data

        user_data_df = pd.DataFrame(
            {
                'guild_id': [item[0] for item in messages],
                'message_content': [item[1] for item in messages],
                'message_timestamp': [item[2] for item in messages],
                'join_timestamp': [item[1] for item in joins],
                'role_change': [item[1] for item in roles],
                'role_timestamp': [item[2] for item in roles],
                'interaction_type': [item[1] for item in interactions],
                'interaction_timestamp': [item[2] for item in interactions]
            }
        )

        account_age_days = (datetime.datetime.now(datetime.timezone.utc) - user_data_df['join_timestamp'].min()).days
        account_age_weeks = account_age_days / 7
        server_count = len(user_data_df['guild_id'].unique())
        message_rate = user_data_df['message_timestamp'].count() / ((user_data_df['message_timestamp'].max() - user_data_df['message_timestamp'].min()).total_seconds() / 3600) 
        interaction_rate = user_data_df['interaction_timestamp'].count() / ((user_data_df['interaction_timestamp'].max() - user_data_df['interaction_timestamp'].min()).total_seconds() / 3600)
        role_change_rate = user_data_df['role_timestamp'].count() / ((user_data_df['role_timestamp'].max() - user_data_df['role_timestamp'].min()).total_seconds() / 3600) 

        sentiments = [TextBlob(message).sentiment.polarity for message in user_data_df['message_content']]
        average_sentiment = np.mean(sentiments)
        message_length_avg = user_data_df['message_content'].str.len().mean()
        emoji_count_avg = user_data_df['message_content'].apply(lambda x: len(emoji.emoji_list(x))).mean()
        mention_count_avg = user_data_df['message_content'].apply(lambda x: len(re.findall(r'<@!?\d+>', x))).mean()

        if ip: 
            graph = nx.Graph()
            graph.add_node(user_id)

            # Burayı veritabanından diğer kullanıcıları sorgulayacak şekilde değiştirmeniz gerekiyor
            # ...

            dbscan = DBSCAN(eps=2, min_samples=3)
            clusters = dbscan.fit_predict(nx.to_numpy_matrix(graph))

            if clusters[list(graph.nodes).index(user_id)] != -1:
                logging.warning(f"User {user_id} is part of a suspicious IP cluster!")
                return True 

        features = [
            account_age_weeks,
            server_count,
            message_rate,
            average_sentiment,
            interaction_rate,
            role_change_rate,
            message_length_avg,
            emoji_count_avg,
            mention_count_avg,
        ]

        scaler = MinMaxScaler()
        scaled_features = scaler.fit_transform(np.array(features).reshape(1, -1))

        if ml_model is None:
            try:
                with open(ml_model_filename, 'rb') as f:
                    ml_model = pickle.load(f)
            except FileNotFoundError:
                ml_model = anomaly.IsolationForest()

        anomaly_score = ml_model.predict_one(dict(zip(range(len(scaled_features[0])), scaled_features[0])))
        ml_model.learn_one(dict(zip(range(len(scaled_features[0])), scaled_features[0])))

        global anomaly_threshold
        if anomaly_score <= anomaly_threshold:
            return True 
        else:
            anomaly_threshold = 0.9 * anomaly_threshold + 0.1 * anomaly_score  
        return False
    else:
        return False

async def collect_user_data(member, guild, event_type, event_data):
    db_connection = sqlite3.connect(db_name)
    cursor = db_connection.cursor()

    try:
        cursor.execute("SELECT * FROM user_data WHERE user_id = ?", (member.id,))
        user_data = cursor.fetchone()
    except:
        user_data = None

    if user_data:
        messages, joins, roles, interactions, ip, suspicious_actions = user_data

        if event_type == 'message':
            messages.append((guild.id, event_data, datetime.datetime.now(datetime.timezone.utc)))
        elif event_type == 'join':
            joins.append((guild.id, event_data, datetime.datetime.now(datetime.timezone.utc)))
        elif event_type == 'role_update':
            roles.append((guild.id, event_data, datetime.datetime.now(datetime.timezone.utc)))
        elif event_type == 'interaction':
            interactions.append((guild.id, event_data, datetime.datetime.now(datetime.timezone.utc)))
        elif event_type == 'ip':
            ip = event_data

        cursor.execute('''
            UPDATE user_data SET messages = ?, joins = ?, roles = ?, interactions = ?, ip = ?, suspicious_actions = ?
            WHERE user_id = ?
        ''', (messages, joins, roles, interactions, ip, suspicious_actions, member.id))
        db_connection.commit()

    else:
        if event_type == 'message':
            messages = [(guild.id, event_data, datetime.datetime.now(datetime.timezone.utc))]
        else:
            messages = []

        if event_type == 'join':
            joins = [(guild.id, event_data, datetime.datetime.now(datetime.timezone.utc))]
        else:
            joins = []

        if event_type == 'role_update':
            roles = [(guild.id, event_data, datetime.datetime.now(datetime.timezone.utc))]
        else:
            roles = []

        if event_type == 'interaction':
            interactions = [(guild.id, event_data, datetime.datetime.now(datetime.timezone.utc))]
        else:
            interactions = []

        if event_type == 'ip':
            ip = event_data
        else:
            ip = None

        cursor.execute('''
            INSERT INTO user_data (user_id, messages, joins, roles, interactions, ip, suspicious_actions)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (member.id, messages, joins, roles, interactions, ip, 0))
        db_connection.commit()

    db_connection.close()

def get_suspicious_actions(user_id):
    db_connection = sqlite3.connect(db_name)
    cursor = db_connection.cursor()
    cursor.execute("SELECT suspicious_actions FROM user_data WHERE user_id = ?", (user_id,))
    suspicious_actions = cursor.fetchone()[0]
    db_connection.close()
    return suspicious_actions

# --- Event Handlers ---
@bot.event
async def on_member_join(member):
    guild_id = member.guild.id
    current_time = datetime.datetime.now(datetime.timezone.utc)
    member_join_times[guild_id].append(current_time)
    await check_for_raid(member.guild)

    account_age = (current_time - member.created_at).total_seconds()
    if account_age < 60 * 60 * 24 * 7:
        logging.warning(f"New member {member.name} has a young account (less than a week old).")

    await collect_user_data(member, member.guild, 'join', None)

    ip_address = await get_ip_from_cloudflare(member.id)
    if ip_address:
        await collect_user_data(member, member.guild, 'ip', ip_address)

@bot.event
async def on_message(message):
    if message.author.bot:
        return

    current_time = datetime.datetime.now(datetime.timezone.utc)
    user_message_deque = user_messages[message.author.id]

    user_message_deque.append((message.content, current_time))
    if len(user_message_deque) > SPAM_THRESHOLD:
        time_diff = (current_time - user_message_deque[0][1]).total_seconds()
        if time_diff <= SPAM_TIME:
            if len(user_message_deque) >= SPAM_THRESHOLD:
                warning_message = await message.channel.send(f"{message.author.mention}, your message was deleted due to spam.")
                await message.delete()
                logging.warning(f"Deleted spam message from {message.author.name}.")
                user_message_deque.popleft()
                try:
                    await asyncio.sleep(10)
                    await warning_message.delete()
                except discord.errors.HTTPException:
                    logging.error(f"Error deleting warning message for spam: {message.author.name}")
        else:
            user_message_deque.popleft()

    last_message_time = user_message_deque[0][1] if user_message_deque else current_time
    if (current_time - last_message_time).total_seconds() < SLOW_MODE_DELAY:
        warning_message = await message.channel.send(f"{message.author.mention}, you are sending messages too quickly. Please wait a moment.")
        await message.delete()
        logging.warning(f"Deleted message from {message.author.name} due to slow mode.")
        try:
            await asyncio.sleep(10)
            await warning_message.delete()
        except discord.errors.HTTPException:
            logging.error(f"Error deleting warning message for slow mode: {message.author.name}")
        return

    message_history[message.author.id].append(message.content)
    if len(message_history[message.author.id]) >= DUPLICATE_MSG_THRESHOLD:
        recent_messages = list(message_history[message.author.id])
        if all(is_similar(recent_messages[-1], msg) for msg in recent_messages[:-1]):
            warning_message = await message.channel.send(f"{message.author.mention}, your message was deleted because it was a duplicate.")
            await message.delete()
            logging.warning(f"Deleted duplicate message from {message.author.name}.")
            try:
                await asyncio.sleep(10)
                await warning_message.delete()
            except discord.errors.HTTPException:
                logging.error(f"Error deleting warning message for duplicate: {message.author.name}")
            return

    if len(message.content) > 0:
        capitalization_ratio = sum(char.isupper() for char in message.content) / len(message.content)
        if capitalization_ratio > CAPITALIZATION_THRESHOLD:
            warning_message = await message.channel.send(f"{message.author.mention}, your message was deleted due to excessive capitalization.")
            await message.delete()
            logging.warning(f"Deleted message with excessive capitalization from {message.author.name}.")
            try:
                await asyncio.sleep(10)
                await warning_message.delete()
            except discord.errors.HTTPException:
                logging.error(f"Error deleting warning message for capitalization: {message.author.name}")
            return

    if contains_excessive_emojis(message.content):
        warning_message = await message.channel.send(f"{message.author.mention}, your message was deleted due to excessive emojis.")
        await message.delete()
        logging.warning(f"Deleted message with excessive emojis from {message.author.name}.")
        try:
            await asyncio.sleep(10)
            await warning_message.delete()
        except discord.errors.HTTPException:
            logging.error(f"Error deleting warning message for emojis: {message.author.name}")
        return

    if is_link(message.content):
        link = re.search(r'(https?://\S+)', message.content).group(0)
        if not await analyze_link_safety(link):
            warning_message = await message.channel.send(f"{message.author.mention}, your message contained an unsafe link and has been deleted.")
            await message.delete()
            logging.warning(f"Deleted message with unsafe link from {message.author.name}.")
            try:
                await asyncio.sleep(10)
                await warning_message.delete()
            except discord.errors.HTTPException:
                logging.error(f"Error deleting warning message for unsafe link: {message.author.name}")
        else:
            await message.channel.send(f"{message.author.mention}, your message contained a safe link.")
        return

    if message.attachments:
        for attachment in message.attachments:
            try:
                file_url = attachment.url
                if not await analyze_file_safety(file_url):
                    warning_message = await message.channel.send(f"{message.author.mention}, your message contained an unsafe file and has been deleted.")
                    await message.delete()
                    logging.warning(f"Deleted message with unsafe file from {message.author.name}.")
                    try:
                        await asyncio.sleep(10)
                        await warning_message.delete()
                    except discord.errors.HTTPException:
                        logging.error(f"Error deleting warning message for unsafe file: {message.author.name}")
                else:
                    await message.channel.send(f"{message.author.mention}, your message contained a safe file.")

                if attachment.url.lower().endswith(('png', 'jpg', 'jpeg', 'gif')):
                    image_hash = await hash_image(attachment.url)
                    if image_hash and is_duplicate_image(message.author.id, image_hash, current_time):
                        warning_message = await message.channel.send(f"{message.author.mention}, you already posted this image!")
                        await message.delete()
                        logging.warning(f"Deleted duplicate image from {message.author.name}.")
                        try:
                            await asyncio.sleep(10)
                            await warning_message.delete()
                        except discord.errors.HTTPException:
                            logging.error(f"Error deleting warning message for duplicate image: {message.author.name}")
                        return

                    if image_hash:
                        user_image_hashes[message.author.id].append((image_hash, current_time))

            except Exception as e:
                logging.error(f"Error analyzing file attachment: {e}")
                return

    if message.author.id in spam_warnings:
        if spam_warnings[message.author.id] >= WARNING_LIMIT:
            await mute_user(message.author, MUTE_DURATION_5M)
            spam_warnings[message.author.id] = 0
        else:
            spam_warnings[message.author.id] += 1

    if message.author.id in suspicious_accounts:
        logging.warning(f"Suspicious account {message.author.name} sent a message.")

    await collect_user_data(message.author, message.guild, 'message', message.content)

    if analyze_user_data(message.author.id):
        db_connection = sqlite3.connect(db_name)
        cursor = db_connection.cursor()
        cursor.execute("UPDATE user_data SET suspicious_actions = suspicious_actions + 1 WHERE user_id = ?", (message.author.id,))
        db_connection.commit()
        db_connection.close()

        suspicious_actions = get_suspicious_actions(message.author.id)

        if suspicious_actions >= SUSPICIOUS_ACTIVITY_THRESHOLD:
            try:
                await message.author.kick(reason="Suspicious activity detected")
                logging.info(f"Kicked member {message.author.name} due to suspicious activity.")
            except discord.Forbidden:
                logging.error(f"Failed to kick member {message.author.name}.")
            except Exception as e:
                logging.error(f"Error kicking member {message.author.name}: {e}")
            db_connection = sqlite3.connect(db_name)
            cursor = db_connection.cursor()
            cursor.execute("UPDATE user_data SET suspicious_actions = 0 WHERE user_id = ?", (message.author.id,))
            db_connection.commit()
            db_connection.close()

@bot.event
async def on_member_update(before, after):
    if before.roles != after.roles:
        await collect_user_data(after, after.guild, 'role_update', after.roles)
        if analyze_user_data(after.id):
            db_connection = sqlite3.connect(db_name)
            cursor = db_connection.cursor()
            cursor.execute("UPDATE user_data SET suspicious_actions = suspicious_actions + 1 WHERE user_id = ?", (after.id,))
            db_connection.commit()
            db_connection.close()

            suspicious_actions = get_suspicious_actions(after.id)

            if suspicious_actions >= SUSPICIOUS_ACTIVITY_THRESHOLD:
                try:
                    await after.kick(reason="Suspicious activity detected")
                    logging.info(f"Kicked member {after.name} due to suspicious activity.")
                except discord.Forbidden:
                    logging.error(f"Failed to kick member {after.name}.")
                except Exception as e:
                    logging.error(f"Error kicking member {after.name}: {e}")
            db_connection = sqlite3.connect(db_name)
            cursor = db_connection.cursor()
            cursor.execute("UPDATE user_data SET suspicious_actions = 0 WHERE user_id = ?", (after.id,))
            db_connection.commit()
            db_connection.close()

@bot.event
async def on_raw_reaction_add(payload):
    await collect_user_data(await bot.fetch_user(payload.user_id), await bot.fetch_guild(payload.guild_id), 'interaction', payload.emoji.name)
    if analyze_user_data(payload.user_id):
        db_connection = sqlite3.connect(db_name)
        cursor = db_connection.cursor()
        cursor.execute("UPDATE user_data SET suspicious_actions = suspicious_actions + 1 WHERE user_id = ?", (payload.user_id,))
        db_connection.commit()
        db_connection.close()

        suspicious_actions = get_suspicious_actions(payload.user_id)

        if suspicious_actions >= SUSPICIOUS_ACTIVITY_THRESHOLD:
            try:
                await bot.fetch_user(payload.user_id).kick(reason="Suspicious activity detected")
                logging.info(f"Kicked member {payload.user_id} due to suspicious activity.")
            except discord.Forbidden:
                logging.error(f"Failed to kick member {payload.user_id}.")
            except Exception as e:
                logging.error(f"Error kicking member {payload.user_id}: {e}")
        db_connection = sqlite3.connect(db_name)
        cursor = db_connection.cursor()
        cursor.execute("UPDATE user_data SET suspicious_actions = 0 WHERE user_id = ?", (payload.user_id,))
        db_connection.commit()
        db_connection.close()

@bot.event
async def on_raw_reaction_remove(payload):
    await collect_user_data(await bot.fetch_user(payload.user_id), await bot.fetch_guild(payload.guild_id), 'interaction', payload.emoji.name)
    if analyze_user_data(payload.user_id):
        db_connection = sqlite3.connect(db_name)
        cursor = db_connection.cursor()
        cursor.execute("UPDATE user_data SET suspicious_actions = suspicious_actions + 1 WHERE user_id = ?", (payload.user_id,))
        db_connection.commit()
        db_connection.close()

        suspicious_actions = get_suspicious_actions(payload.user_id)

        if suspicious_actions >= SUSPICIOUS_ACTIVITY_THRESHOLD:
            try:
                await bot.fetch_user(payload.user_id).kick(reason="Suspicious activity detected")
                logging.info(f"Kicked member {payload.user_id} due to suspicious activity.")
            except discord.Forbidden:
                logging.error(f"Failed to kick member {payload.user_id}.")
            except Exception as e:
                logging.error(f"Error kicking member {payload.user_id}: {e}")
        db_connection = sqlite3.connect(db_name)
        cursor = db_connection.cursor()
        cursor.execute("UPDATE user_data SET suspicious_actions = 0 WHERE user_id = ?", (payload.user_id,))
        db_connection.commit()
        db_connection.close()

@bot.event
async def on_ready():
    logging.info(f'Logged in as {bot.user.name}')
    bot.loop.create_task(update_status())

# --- Run Bot ---
bot.run(TOKEN)
