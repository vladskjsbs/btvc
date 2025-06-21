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
import aiofiles
import ctypes
import time
from termcolor import colored
import bech32
from functools import lru_cache

# Глобальные счетчики
total_checked = 0
total_balance = 0
total_operations = 0
start_time = time.time()  

is_exe = hasattr(sys, 'frozen')

if is_exe:
    operations_file = "operations_count.txt"
    if os.path.exists(operations_file):
        with open(operations_file, "r") as f:
            total_operations = int(f.read().strip())

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

@lru_cache(maxsize=10000)
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

async def save_wallet(mnemonic_phrase, addresses, wallet_import_format, file_path):
    async with aiofiles.open(file_path, 'a') as f:
        await f.write(f"{datetime.now()}: Mnemonic Phrase: {mnemonic_phrase}\n")
        await f.write(f"Private Key: {wallet_import_format}\n")
        for address_type, address in addresses.items():
            await f.write(f"{address_type} Address: {address}\n")
        await f.write("\n\n")

async def update_status_bar():
    global total_checked, total_balance, start_time
    while True:
        elapsed_time = time.time() - start_time
        checks_per_second = total_checked / elapsed_time
        title = f"bvtc by stikcs || Проверок: {total_checked} ({checks_per_second:.2f} проверок/с) || Баланс: {total_balance:.8f} BTC"
        if os.name == 'nt':
            ctypes.windll.kernel32.SetConsoleTitleW(title)
        else:
            print(f"\033]0;{title}\007", end='', flush=True)
        await asyncio.sleep(0.1)

async def worker(output_directory: str, session: aiohttp.ClientSession, activity_event: asyncio.Event) -> None:
    global total_checked, total_balance, total_operations
    while True:
        mnemonic_phrase = Mnemonic("english").generate(128)
        private_key_bytes, addresses, wallet_import_format = generate_key_and_addresses(mnemonic_phrase)

        balances = await get_balances(session, tuple(addresses.values()))

        mnemonic_str = colored(f"Mnemonic: {mnemonic_phrase}", 'cyan')
        private_key_str = colored(f"Private Key: {private_key_bytes.hex()}", 'magenta')
        print(f"{mnemonic_str}\n{private_key_str}")

        for address_type, address in addresses.items():
            address_str = colored(f"{address_type} Address: {address}", 'yellow')
            print(f"{address_str}")

        print("\n\n")

        total_checked += len(addresses)

        total_balance_for_wallet = sum(balances.values())
        if total_balance_for_wallet > 0:
            file_name = f"btvc_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
            file_path = os.path.join(output_directory, file_name)
            await save_wallet(mnemonic_phrase, addresses, wallet_import_format, file_path)
            total_operations += 1
            total_balance += total_balance_for_wallet

            if is_exe:
                with open(operations_file, "w") as f:
                    f.write(str(total_operations))

        if total_checked % 500000 == 0:  # очистка кеша
            gc.collect()

        activity_event.set()
        await asyncio.sleep(0.005) 

async def monitor_activity(activity_event: asyncio.Event, session: aiohttp.ClientSession, output_directory: str) -> None:
    num_workers = 50
    global start_time, total_checked
    while True:
        activity_event.clear()
        try:
            await asyncio.wait_for(activity_event.wait(), timeout=10)
        except asyncio.TimeoutError:
            num_workers += 5
            print(colored(f"Увеличение числа воркеров до {num_workers}...", 'red'))
            await start_workers(output_directory, session, num_workers)
        await asyncio.sleep(2)

async def start_workers(output_directory: str, session: aiohttp.ClientSession, num_workers=50) -> None:
    activity_event = asyncio.Event()
    tasks = []

    for _ in range(num_workers):
        tasks.append(asyncio.create_task(worker(output_directory, session, activity_event)))
    
    tasks.append(asyncio.create_task(update_status_bar()))
    tasks.append(asyncio.create_task(monitor_activity(activity_event, session, output_directory)))

    await asyncio.gather(*tasks)

async def main():
    output_directory = "wallets"
    os.makedirs(output_directory, exist_ok=True)

    async with aiohttp.ClientSession() as session:
        await start_workers(output_directory, session)

if __name__ == "__main__":
    asyncio.run(main())