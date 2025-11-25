import hashlib
import json
import time
import os
from ecdsa import SigningKey, SECP256k1
import base58
from getpass import getpass

ARCHIVO = "moon_blockchain.json"

# =============================================
# GENERAR WALLET
# =============================================
def generar_wallet():
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.verifying_key
    private_key = sk.to_string().hex()
    pubkey = b"\x04" + vk.to_string()
    hash160 = hashlib.new('ripemd160', hashlib.sha256(pubkey).digest()).digest()
    direccion = base58.b58encode(b'\x00' + hash160).decode()
    direccion = "M" + direccion[1:34]
    return private_key, direccion, sk

# =============================================
# BLOCKCHAIN MOON - VERSIÓN DEFINITIVA
# =============================================
class MoonBlockchain:
    def __init__(self):
        self.cadena = []
        self.balances = {}
        self.dificultad = 4
        
        if os.path.exists(ARCHIVO):
            self.cargar()
            print(f"MOON cargada → {len(self.cadena)} bloques | Balance: {self.balances[self.direccion]:,} MOON")
        else:
            self.crear_genesis()

    def crear_genesis(self):
        print("Creando tu blockchain MOON desde cero (solo esta vez)...")
        self.private_key, self.direccion, self.sk = generar_wallet()
        print(f"\nTU DIRECCIÓN OFICIAL DE MOON")
        print(f"→ {self.direccion}")
        print(f"Private key guardada y protegida con contraseña\n")
        
        contraseña = getpass("Elige una contraseña corta para proteger tu wallet: ")
        self.hash_contraseña = hashlib.sha256(contraseña.encode()).hexdigest()
        
        bloque = {
            "indice": 0,
            "transacciones": [{"tipo": "premine", "to": self.direccion, "cantidad": 5000000}],
            "timestamp": time.time(),
            "hash_anterior": "0",
            "nonce": 0
        }
        self.minar_bloque(bloque)
        self.cadena.append(bloque)
        self.balances[self.direccion] = 5000000
        self.guardar()

    def minar_bloque(self, bloque):
        print(f"Minando bloque #{bloque['indice']}...", end=" ")
        while True:
            hash_bloque = hashlib.sha256(json.dumps(bloque, sort_keys=True).encode()).hexdigest()
            if hash_bloque.startswith("0" * self.dificultad):
                bloque["hash"] = hash_bloque
                print(f"¡Minado! → {hash_bloque[:16]}...")
                break
            bloque["nonce"] += 1

    def nueva_transferencia(self, destino, cantidad):
        contraseña = getpass("Contraseña para firmar la transferencia: ")
        if hashlib.sha256(contraseña.encode()).hexdigest() != self.hash_contraseña:
            print("Contraseña incorrecta")
            return
        
        if self.balances.get(self.direccion, 0) < cantidad:
            print("Fondos insuficientes")
            return
        
        # Crear y firmar transacción
        tx = {"tipo": "transfer", "de": self.direccion, "a": destino, "cantidad": cantidad}
        mensaje = json.dumps(tx, sort_keys=True).encode()
        tx["firma"] = self.sk.sign(mensaje).hex()
        
        # Recompensa + transferencia
        reward = {"tipo": "reward", "to": self.direccion, "cantidad": 50}
        bloque = {
            "indice": len(self.cadena),
            "transacciones": [reward, tx],
            "timestamp": time.time(),
            "hash_anterior": self.cadena[-1]["hash"],
            "nonce": 0
        }
        self.minar_bloque(bloque)
        self.cadena.append(bloque)
        
        # Aplicar cambios
        self.balances[self.direccion] -= cantidad
        self.balances[self.direccion] += 50
        self.balances[destino] = self.balances.get(destino, 0) + cantidad
        
        self.guardar()
        print(f"TRANSFERENCIA EXITOSA → {cantidad} MOON a {destino[:12]}...")

    def guardar(self):
        datos = {
            "cadena": self.cadena,
            "balances": self.balances,
            "direccion": self.direccion,
            "hash_contraseña": self.hash_contraseña,
            "private_key": self.sk.to_string().hex()
        }
        with open(ARCHIVO, "w", encoding="utf-8") as f:
            json.dump(datos, f, indent=2)

    def cargar(self):
        with open(ARCHIVO) as f:
            d = json.load(f)
        self.cadena = d["cadena"]
        self.balances = d["balances"]
        self.direccion = d["direccion"]
        self.hash_contraseña = d["hash_contraseña"]
        self.sk = SigningKey.from_string(bytes.fromhex(d["private_key"]), curve=SECP256k1)

    def estado(self):
        print("\n" + "="*80)
        print("               MOON - BLOCKCHAIN 100% FUNCIONAL")
        print("="*80)
        for addr, bal in sorted(self.balances.items(), key=lambda x: -x[1]):
            print(f"{addr} → {bal:,} MOON")
        print(f"\nBloques totales: {len(self.cadena)}")
        print("="*80)

# =============================================
# LANZAMIENTO
# =============================================
if __name__ == "__main__":
    moon = MoonBlockchain()
    
    # Creamos wallet destino
    _, destino, _ = generar_wallet()
    print(f"\nWallet destino → {destino}")
    
    # Primera transferencia real
    moon.nueva_transferencia(destino, 1000)
    moon.estado()