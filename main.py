
import os
import asyncio
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta

import discord
from discord.ext import commands
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("DISCORD_TOKEN")
LOG_CHANNEL_ID = int(os.getenv("LOG_CHANNEL_ID", "0"))

TRUSTED_USERS = {
    int(x.strip())
    for x in os.getenv("TRUSTED_USERS", "").split(",")
    if x.strip().isdigit()
}

WINDOW_SECONDS = 60
NUKE_THRESHOLD = 3
PUNISH_COOLDOWN = 300

intents = discord.Intents.default()
intents.guilds = True
intents.members = True

bot = commands.Bot(
    command_prefix="!",
    intents=intents
)

# Lưu hành vi theo ID người thực hiện
actions = defaultdict(deque)
processed_entries = set()
punish_times = {}

DANGEROUS_PERMISSIONS = [
    "administrator",
    "manage_guild",
    "manage_roles",
    "manage_channels",
    "ban_members",
    "kick_members",
    "manage_webhooks",
]


async def send_log(guild, message):
    channel = guild.get_channel(LOG_CHANNEL_ID)

    if channel is None:
        return

    embed = discord.Embed(
        title="🛡️ HTHT ANTI-NUKE",
        description=message,
        color=discord.Color.red(),
        timestamp=datetime.now(timezone.utc)
    )

    try:
        await channel.send(embed=embed)
    except discord.HTTPException:
        pass


async def remove_dangerous_roles(member):
    guild = member.guild
    bot_member = guild.me

    if bot_member is None:
        return []

    removable = []

    for role in member.roles:
        if role.is_default() or role.managed:
            continue

        if role >= bot_member.top_role:
            continue

        if any(
            getattr(role.permissions, permission, False)
            for permission in DANGEROUS_PERMISSIONS
        ):
            removable.append(role)

    if removable:
        await member.remove_roles(
            *removable,
            reason="HTHT Anti-Nuke: suspicious activity"
        )

    return removable


async def punish_executor(guild, user_id, reason):
    member = guild.get_member(user_id)

    if member is None:
        return

    if member.id == guild.owner_id:
        return

    now = datetime.now(timezone.utc).timestamp()

    if now - punish_times.get(user_id, 0) < PUNISH_COOLDOWN:
        return

    punish_times[user_id] = now

    try:
        removed = await remove_dangerous_roles(member)

        # Timeout là biện pháp bổ sung, không thay thế
        # việc thu hồi quyền Administrator.
        if not removed and member.top_role < guild.me.top_role:
            await member.timeout(
                timedelta(hours=1),
                reason="HTHT Anti-Nuke protection"
            )

        await send_log(
            guild,
            f"🚨 **PHÁT HIỆN HÀNH VI NUKE**\n"
            f"Người thực hiện: {member.mention}\n"
            f"User ID: `{user_id}`\n"
            f"Lý do: `{reason}`\n"
            f"Role đã thu hồi: `{len(removed)}`"
        )

    except discord.Forbidden:
        await send_log(
            guild,
            f"⚠️ Không đủ quyền xử lý người dùng `{user_id}`. "
            "Hãy kiểm tra thứ tự role của bot."
        )

    except discord.HTTPException as error:
        await send_log(
            guild,
            f"⚠️ Lỗi xử lý người dùng `{user_id}`: `{error}`"
        )


async def record_action(guild, action, target_id=None):
    if guild.me is None:
        return

    try:
        async for entry in guild.audit_logs(
            limit=10,
            action=action
        ):
            # Chỉ nhận log mới trong 15 giây
            age = (
                datetime.now(timezone.utc) - entry.created_at
            ).total_seconds()

            if age < 0 or age > 15:
                continue

            if entry.id in processed_entries:
                continue

            if target_id is not None:
                if getattr(entry.target, "id", None) != target_id:
                    continue

            executor = entry.user

            if executor is None:
                continue

            processed_entries.add(entry.id)

            # Không xử lý Owner hoặc tài khoản tin cậy
            if executor.id == guild.owner_id:
                continue

            if executor.id in TRUSTED_USERS:
                continue

            now = datetime.now(timezone.utc).timestamp()
            history = actions[(guild.id, executor.id)]

            history.append(now)

            while history and now - history[0] > WINDOW_SECONDS:
                history.popleft()

            await send_log(
                guild,
                f"📋 Hành động: `{action.name}`\n"
                f"Người thực hiện: {executor.mention}\n"
                f"Số hành động trong 60 giây: `{len(history)}`"
            )

            if len(history) >= NUKE_THRESHOLD:
                await punish_executor(
                    guild,
                    executor.id,
                    f"{len(history)} hành động trong 60 giây"
                )

    except discord.Forbidden:
        await send_log(
            guild,
            "⚠️ Bot không đọc được Audit Log. "
            "Hãy cấp quyền View Audit Log."
        )

    except discord.HTTPException:
        pass


# =========================
# CHANNEL PROTECTION
# =========================

@bot.event
async def on_guild_channel_delete(channel):
    await record_action(
        channel.guild,
        discord.AuditLogAction.channel_delete,
        channel.id
    )


@bot.event
async def on_guild_channel_create(channel):
    await record_action(
        channel.guild,
        discord.AuditLogAction.channel_create,
        channel.id
    )


# =========================
# ROLE PROTECTION
# =========================

@bot.event
async def on_guild_role_delete(role):
    await record_action(
        role.guild,
        discord.AuditLogAction.role_delete,
        role.id
    )


@bot.event
async def on_guild_role_create(role):
    await record_action(
        role.guild,
        discord.AuditLogAction.role_create,
        role.id
    )


@bot.event
async def on_guild_role_update(before, after):
    await record_action(
        after.guild,
        discord.AuditLogAction.role_update,
        after.id
    )


# =========================
# MEMBER PROTECTION
# =========================

@bot.event
async def on_member_ban(guild, user):
    await record_action(
        guild,
        discord.AuditLogAction.ban,
        user.id
    )


@bot.event
async def on_member_remove(member):
    await record_action(
        member.guild,
        discord.AuditLogAction.kick,
        member.id
    )


# =========================
# WEBHOOK PROTECTION
# =========================

@bot.event
async def on_webhooks_update(channel):
    for action in [
        discord.AuditLogAction.webhook_create,
        discord.AuditLogAction.webhook_update,
        discord.AuditLogAction.webhook_delete,
    ]:
        await record_action(channel.guild, action)


# =========================
# SERVER PROTECTION
# =========================

@bot.event
async def on_guild_update(before, after):
    await record_action(
        after,
        discord.AuditLogAction.guild_update
    )


# =========================
# SLASH COMMANDS
# =========================

@bot.tree.command(
    name="antinuke_status",
    description="Kiểm tra trạng thái HTHT Anti-Nuke"
)
async def antinuke_status(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message(
            "Lệnh chỉ sử dụng trong server.",
            ephemeral=True
        )
        return

    embed = discord.Embed(
        title="🛡️ HTHT ANTI-NUKE STATUS",
        color=discord.Color.green()
    )

    embed.add_field(
        name="Protection",
        value="ACTIVE",
        inline=True
    )

    embed.add_field(
        name="Threshold",
        value=f"{NUKE_THRESHOLD} actions / {WINDOW_SECONDS}s",
        inline=True
    )

    embed.add_field(
        name="Log Channel",
        value=f"<#{LOG_CHANNEL_ID}>",
        inline=True
    )

    await interaction.response.send_message(
        embed=embed,
        ephemeral=True
    )


@bot.event
async def on_ready():
    if not getattr(bot, "synced", False):
        await bot.tree.sync()
        bot.synced = True

    print(f"HTHT ANTI-NUKE ONLINE: {bot.user}")

    for guild in bot.guilds:
        await send_log(
            guild,
            "🟢 HTHT ANTI-NUKE đã khởi động."
        )


if not TOKEN:
    raise RuntimeError("Chưa cấu hình DISCORD_TOKEN trong .env")

bot.run(TOKEN)
