# ChainSentinel MCP Server

Claude Desktop üzerinden ChainSentinel'i doğrudan kullanmanızı sağlar.

## Kurulum

### 1. Gerekli paketleri yükleyin
```bash
pip install mcp requests
```

### 2. Claude Desktop config'ini güncelleyin

Windows'ta `%APPDATA%\Claude\claude_desktop_config.json` dosyasını açın ve aşağıdaki içeriği ekleyin:
```json
{
    "mcpServers": {
        "chainsentinel": {
            "command": "python",
            "args": ["mcp_server/server.py"],
            "cwd": "C:\\Users\\Taha\\Projects\\ChainSentinel"
        }
    }
}
```

### 3. ChainSentinel backend'ini başlatın
```bash
cd C:\Users\Taha\Projects\ChainSentinel
uvicorn backend.main:app --host 0.0.0.0 --port 9000
```

### 4. Claude Desktop'ı yeniden başlatın

## Kullanılabilir Komutlar

Claude Desktop'ta şu komutları kullanabilirsiniz:

- **"Ağı tara"** → LAN'daki cihazları keşfeder
- **"IoT cihazını tara"** → IoT güvenlik testi yapar
- **"Tedarikçi portalını tara"** → Web portal güvenlik testi yapar
- **"WMS API'yi tara"** → API güvenlik testi yapar
- **"Tarama sonuçlarını göster"** → Belirli taramanın detaylarını getirir
- **"Tüm bulguları listele"** → Severity'ye göre filtrelenmiş bulgu listesi
- **"Tarama geçmişini göster"** → Geçmiş taramalar
- **"Bulguları analiz et"** → AI ile risk analizi, saldırı zinciri, MITRE mapping

## Notlar

- Backend'in çalışıyor olması gerekir (localhost:9000)
- AI analizi için dashboard'dan AI ayarlarının yapılmış olması gerekir
- Ağ taraması için Nmap yüklü olmalıdır
