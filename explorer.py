from flask import Flask, render_template_string
import json
import qrcode
from io import BytesIO
import base64
import time

app = Flask(__name__)
ARCHIVO = "moon_blockchain.json"

def cargar_blockchain():
    with open(ARCHIVO, "r", encoding="utf-8") as f:
        return json.load(f)

@app.route("/")
def explorer():
    try:
        data = cargar_blockchain()
    except:
        return "<h1 style='color:#f00;text-align:center;'>ERROR: No se encuentra moon_blockchain.json<br>Asegurate de tenerlo en la carpeta</h1>"

    cadena = data["cadena"]
    balances = data["balances"]
    total_bloques = len(cadena)

    # QR de tu dirección
    qr = qrcode.QRCode()
    qr.add_data(data["direccion"])
    img = qrcode.make(qr)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    qr_img = base64.b64encode(buffered.getvalue()).decode()

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>MOON EXPLORER • Knki</title>
        <meta charset="utf-8">
        <style>
            body {{ font-family: 'Courier New', monospace; background: #000; color: #0f0; padding: 20px; }}
            h1 {{ text-align: center; color: #0ff; font-size: 3.5em; margin: 30px; }}
            h2 {{ text-align: center; color: #0f8; }}
            .block {{ background: #111; margin: 20px 0; padding: 20px; border: 2px solid #0f0; border-radius: 10px; }}
            .hash {{ color: #ff0; }}
            .addr {{ color: #f0f; font-weight: bold; }}
            table {{ width: 100%; border-collapse: collapse; margin: 30px 0; }}
            th, td {{ border: 1px solid #0f0; padding: 12px; }}
            th {{ background: #001; color: #0ff; }}
            .qr {{ text-align: center; margin: 50px; }}
            footer {{ text-align: center; margin-top: 100px; color: #0f0; font-size: 1.3em; }}
        </style>
    </head>
    <body>
        <h1>MOON EXPLORER</h1>
        <h2>Supply máximo: 21.000.000 MOON • Bloques: {total_bloques}</h2>

        <div class="qr">
            <h3>Dirección del creador</h3>
            <p class="addr"><b>{data["direccion"]}</b></p>
            <img src="data:image/png;base64,{qr_img}" width="300">
        </div>

        <h2>Balances actuales</h2>
        <table>
            <tr><th>Dirección</th><th>Balance</th></tr>
            {''.join(f'<tr><td class="addr">{addr}</td><td>{bal:,} MOON</td></tr>' for addr, bal in sorted(balances.items(), key=lambda x: -x[1]))}
        </table>

        <h2>Últimos bloques</h2>
        {''.join(f'''
        <div class="block">
            <b>Bloque #{b["indice"]}</b> • Hash: <span class="hash">{b.get("hash","genesis")[:16]}...</span><br>
            Transacciones: {len(b["transacciones"])} • {time.strftime("%d/%m/%Y %H:%M:%S", time.localtime(b["timestamp"]))}
        </div>''' for b in cadena[-10:][::-1])}

        <footer>
            <strong>MOON</strong> • Creada 100% por <strong>Knki</strong><br>
            24 de noviembre de 2025 • Primera blockchain propia real
        </footer>
    </body>
    </html>
    """
    return render_template_string(html)

if __name__ == "__main__":
    print("="*70)
    print("           MOON EXPLORER OFICIAL - by Knki")
    print("           http://localhost:5000")
    print("="*70)
    app.run(host="0.0.0.0", port=5000, debug=False)