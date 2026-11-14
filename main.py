import os
import io
import ssl
import socket
import secrets
import datetime
import tempfile
import threading
import asyncio
import urllib.parse
from ipaddress import ip_address
from aiohttp import web
import qrcode
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import flet as ft


def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def create_ssl_context(local_ip: str) -> ssl.SSLContext:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, local_ip),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureQRShare"),
    ])
    san_list = [x509.DNSName("localhost")]
    try:
        san_list.append(x509.IPAddress(ip_address(local_ip)))
    except ValueError:
        pass

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cf:
        cf.write(cert_pem)
        cert_path = cf.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
        kf.write(key_pem)
        key_path = kf.name

    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

    for p in (cert_path, key_path):
        try:
            os.remove(p)
        except OSError:
            pass
    return ssl_ctx


class SecureShareServer:
    def __init__(self, on_file_received_callback=None):
        self.token = secrets.token_urlsafe(24)
        self.shared_files = {}
        self.port = self._find_free_port(8443)
        self.failed_attempts = 0
        self.locked = False
        self.on_file_received = on_file_received_callback

        # تحديد مجلد الحفظ تلقائياً حسب النظام (أندرويد أو آيفون)
        android_dl = "/storage/emulated/0/Download/SecureQRShare"
        ios_docs = os.path.expanduser("~/Documents/Received_Files")
        if os.path.exists("/storage/emulated/0"):
            self.receive_dir = android_dl
        else:
            self.receive_dir = ios_docs
        os.makedirs(self.receive_dir, exist_ok=True)

    @staticmethod
    def _find_free_port(preferred_port: int) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", preferred_port)) != 0:
                return preferred_port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("0.0.0.0", 0))
            return s.getsockname()[1]

    def verify_token(self, request) -> bool:
        if self.locked:
            return False
        req_token = request.query.get("token", "")
        if not req_token or not secrets.compare_digest(req_token, self.token):
            self.failed_attempts += 1
            if self.failed_attempts >= 5:
                self.locked = True
            return False
        return True

    async def index_handler(self, request):
        if not self.verify_token(request):
            return web.Response(text="403 Forbidden: غير مصرح بالدخول", status=403)

        files_html = ""
        for fname in self.shared_files:
            encoded_name = urllib.parse.quote(fname)
            files_html += f"""
            <div class="file-card">
                <span class="fname">📄 {fname}</span>
                <a href="/download/{encoded_name}?token={self.token}" class="btn">تحميل</a>
            </div>
            """

        uploaded_msg = (
            "<div class='alert'>✅ تم استلام الملفات بنجاح!</div>"
            if request.query.get("uploaded") == "1"
            else ""
        )

        html = f"""
        <!DOCTYPE html>
        <html lang="ar" dir="rtl">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>نقل آمن عبر الباركود</title>
            <style>
                * {{ box-sizing: border-box; }}
                body {{ font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; padding: 16px; margin: 0; text-align: center; }}
                .container {{ max-width: 520px; margin: 20px auto; background: #1e293b; padding: 20px; border-radius: 16px; }}
                .file-card {{ background: #0f172a; padding: 12px 16px; margin: 10px 0; border-radius: 10px; display: flex; justify-content: space-between; align-items: center; gap: 10px; }}
                .fname {{ word-break: break-all; text-align: right; font-size: 14px; }}
                .btn {{ background: #10b981; color: white; text-decoration: none; padding: 8px 16px; border-radius: 8px; font-weight: bold; white-space: nowrap; border: none; font-size: 14px; }}
                .upload-box {{ border: 2px dashed #38bdf8; padding: 20px; border-radius: 12px; margin-top: 24px; background: rgba(56, 189, 248, 0.05); }}
                .alert {{ background: #065f46; color: #a7f3d0; padding: 10px; border-radius: 8px; margin-bottom: 15px; font-weight: bold; }}
                input[type="file"] {{ color: #cbd5e1; margin: 12px 0; max-width: 100%; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h2>🔒 جلسة نقل مشفرة (TLS)</h2>
                {uploaded_msg}
                <h4 style="color:#94a3b8;">الملفات المتاحة للتحميل على هاتفك:</h4>
                {files_html if files_html else "<p style='color:#64748b;'>لم يتم تحديد ملفات للإرسال بعد</p>"}
                <div class="upload-box">
                    <h3 style="margin-top:0; color:#38bdf8;">📤 إرسال صور أو ملفات</h3>
                    <form action="/upload?token={self.token}" method="post" enctype="multipart/form-data">
                        <input type="file" name="file" multiple required><br>
                        <button type="submit" class="btn" style="background:#0284c7; width:100%; padding:12px;">رفع وإرسال الآن</button>
                    </form>
                </div>
            </div>
        </body>
        </html>
        """
        return web.Response(text=html, content_type="text/html")

    async def download_handler(self, request):
        if not self.verify_token(request):
            return web.Response(text="403 Forbidden", status=403)
        fname = urllib.parse.unquote(request.match_info["filename"])
        fpath = self.shared_files.get(fname)
        if fpath and os.path.exists(fpath):
            encoded_disp = urllib.parse.quote(fname)
            return web.FileResponse(
                fpath,
                headers={"Content-Disposition": f"attachment; filename*=UTF-8''{encoded_disp}"},
            )
        return web.Response(text="404 Not Found", status=404)

    async def upload_handler(self, request):
        if not self.verify_token(request):
            return web.Response(text="403 Forbidden", status=403)
        reader = await request.multipart()
        while True:
            part = await reader.next()
            if part is None:
                break
            if part.filename:
                safe_name = os.path.basename(part.filename)
                save_path = os.path.join(self.receive_dir, safe_name)
                with open(save_path, "wb") as f:
                    while True:
                        chunk = await part.read_chunk()
                        if not chunk:
                            break
                        f.write(chunk)
                if self.on_file_received:
                    self.on_file_received(safe_name)
        raise web.HTTPFound(f"/?token={self.token}&uploaded=1")

    def start(self, local_ip: str):
        def run_loop():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            app = web.Application(client_max_size=2 * 1024**3)
            app.router.add_get("/", self.index_handler)
            app.router.add_get("/download/{filename}", self.download_handler)
            app.router.add_post("/upload", self.upload_handler)

            ssl_ctx = create_ssl_context(local_ip)
            runner = web.AppRunner(app)
            loop.run_until_complete(runner.setup())
            site = web.TCPSite(runner, "0.0.0.0", self.port, ssl_context=ssl_ctx)
            loop.run_until_complete(site.start())
            loop.run_forever()

        threading.Thread(target=run_loop, daemon=True).start()


def generate_qr_bytes(data: str) -> bytes:
    qr = qrcode.QRCode(box_size=8, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def main(page: ft.Page):
    page.title = "Secure QR Share"
    page.theme_mode = ft.ThemeMode.DARK
    page.rtl = True
    page.scroll = ft.ScrollMode.AUTO
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    page.padding = 20

    shared_files_column = ft.Column(spacing=6)
    received_files_column = ft.Column(spacing=6)

    def on_file_received(filename: str):
        received_files_column.controls.append(
            ft.Text(f"📥 تم استلام: {filename}", color="#38bdf8", size=14)
        )
        page.update()

    local_ip = get_local_ip()
    server = SecureShareServer(on_file_received_callback=on_file_received)
    server.start(local_ip)

    share_url = f"https://{local_ip}:{server.port}/?token={server.token}"
    qr_image = ft.Image(src=generate_qr_bytes(share_url), width=220, height=220)
    url_text = ft.Text(f"الرابط المشفر: https://{local_ip}:{server.port}", size=13, color="#38bdf8")

    async def pick_files_click(e):
        picker = ft.FilePicker()
        files = await picker.pick_files(allow_multiple=True)
        if files:
            for f in files:
                if f.path:
                    server.shared_files[f.name] = f.path
                    shared_files_column.controls.append(
                        ft.Text(f"✅ جاهز للإرسال: {f.name}", color="#4ade80", size=14)
                    )
            page.update()

    def regenerate_token_click(e):
        server.token = secrets.token_urlsafe(24)
        server.failed_attempts = 0
        server.locked = False
        new_url = f"https://{local_ip}:{server.port}/?token={server.token}"
        qr_image.src = generate_qr_bytes(new_url)
        url_text.value = f"الرابط المشفر: https://{local_ip}:{server.port} (محدث)"
        page.update()

    def clear_files_click(e):
        server.shared_files.clear()
        shared_files_column.controls.clear()
        page.update()

    page.add(
        ft.Text("مشاركة آمنة بالباركود 🔒", size=24, weight=ft.FontWeight.BOLD),
        ft.Text("امسح الباركود بكاميرا الآيفون أو الأندرويد للنقل الفوري", color="#94a3b8", size=14),
        ft.Container(content=qr_image, bgcolor="#ffffff", padding=12, border_radius=16, margin=10),
        url_text,
        ft.Row(
            controls=[
                ft.FilledButton(content=ft.Text("📁 اختيار صور أو ملفات"), on_click=pick_files_click),
                ft.OutlinedButton(content=ft.Text("🔄 رمز جديد"), on_click=regenerate_token_click),
                ft.OutlinedButton(content=ft.Text("🗑️ مسح"), on_click=clear_files_click),
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            wrap=True,
        ),
        ft.Divider(height=25),
        ft.Container(
            content=ft.Column([
                ft.Text("📤 الملفات المحددة للمشاركة:", weight=ft.FontWeight.BOLD, size=15),
                shared_files_column,
                ft.Divider(height=15),
                ft.Text("📥 الملفات المستلمة:", weight=ft.FontWeight.BOLD, size=15),
                received_files_column,
            ]),
            width=500,
            padding=15,
            bgcolor="#1e293b",
            border_radius=12,
        ),
    )


if __name__ == "__main__":
    ft.run(main)
